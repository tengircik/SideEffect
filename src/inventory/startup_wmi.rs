//! Read-only, bounded inventory of local permanent WMI event subscriptions.
//!
//! Only the fixed classes in `root\subscription` are queried. Collected WQL,
//! command, and script fields are inert evidence and are never interpreted.

use super::startup_windows::{
    WindowsStartupDiagnostic, WindowsStartupSource, WindowsStartupStatus, diagnostic,
    diagnostic_hresult, elapsed, source_result,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::Instant;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
    CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Ole::{
    SafeArrayAccessData, SafeArrayGetDim, SafeArrayGetLBound, SafeArrayGetUBound,
    SafeArrayUnaccessData,
};
use windows::Win32::System::Variant::{VARIANT, VT_ARRAY, VT_UI1, VariantClear, VariantToString};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_S_TIMEDOUT, WbemLocator,
};
use windows::core::{BSTR, IUnknown, Interface, PCWSTR};

const MAX_WMI_ROWS_PER_CLASS: usize = 2_048;
const MAX_WMI_TOTAL_ROWS: usize = 8_192;
const MAX_WMI_STRING_UNITS: usize = 16_384;
const MAX_WMI_AGGREGATE_UNITS: usize = 2 * 1024 * 1024;
const MAX_WMI_DIAGNOSTICS: usize = 128;
const VT_NULL_VARIANT: u16 = 1;
const WMI_NEXT_TIMEOUT_MS: i32 = 250;
const WMI_NAMESPACE: &str = "ROOT\\subscription";
const WMI_SOURCE: &str = "IWbemLocator/IWbemServices/IEnumWbemClassObject";
const WMI_QUERIES: [(&str, &str); 5] = [
    (
        "__EventFilter",
        "SELECT __RELPATH, Name, CreatorSID, EventNamespace, QueryLanguage, Query FROM __EventFilter",
    ),
    (
        "__EventConsumer",
        "SELECT __RELPATH, __CLASS, CreatorSID FROM __EventConsumer",
    ),
    (
        "__FilterToConsumerBinding",
        "SELECT __RELPATH, CreatorSID, Filter, Consumer, DeliveryQoS FROM __FilterToConsumerBinding",
    ),
    (
        "CommandLineEventConsumer",
        "SELECT __RELPATH, Name, ExecutablePath, CommandLineTemplate FROM CommandLineEventConsumer",
    ),
    (
        "ActiveScriptEventConsumer",
        "SELECT __RELPATH, Name, ScriptFileName, ScriptText FROM ActiveScriptEventConsumer",
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WmiReferenceStatus {
    Resolved,
    Unresolved,
}

#[derive(Clone, Debug, Serialize)]
pub struct WmiEventFilter {
    pub object_path: String,
    pub name: Option<String>,
    pub creator_sid: Option<String>,
    pub event_namespace: Option<String>,
    pub query_language: Option<String>,
    pub query: Option<String>,
    pub evidence: WmiSubscriptionEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WmiConsumerStatus {
    Observed,
    UnsupportedClass,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct WmiEventConsumer {
    pub object_path: String,
    pub class_name: String,
    pub name: Option<String>,
    pub creator_sid: Option<String>,
    pub status: WmiConsumerStatus,
    pub executable_path: Option<String>,
    pub command_line_template: Option<String>,
    pub script_file_name: Option<String>,
    pub script_text: Option<String>,
    pub evidence: WmiSubscriptionEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail_evidence: Option<WmiSubscriptionEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WmiFilterConsumerBinding {
    pub object_path: String,
    pub filter_reference: String,
    pub consumer_reference: String,
    pub filter_reference_status: WmiReferenceStatus,
    pub consumer_reference_status: WmiReferenceStatus,
    pub creator_sid: Option<String>,
    pub delivery_qos: Option<String>,
    pub evidence: WmiSubscriptionEvidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct WmiSubscriptionEvidence {
    pub source: &'static str,
    pub namespace: &'static str,
    pub class_name: &'static str,
    pub object_index: usize,
}

pub(super) struct WmiStartupCollection {
    pub source: WindowsStartupSource,
    pub filters: Vec<WmiEventFilter>,
    pub consumers: Vec<WmiEventConsumer>,
    pub bindings: Vec<WmiFilterConsumerBinding>,
}

struct ComApartment;

impl Drop for ComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

fn set_proxy_security<T: Interface>(proxy: &T) -> windows::core::Result<()> {
    unsafe {
        let unknown: IUnknown = proxy.cast()?;
        CoSetProxyBlanket(
            &unknown,
            10, // RPC_C_AUTHN_WINNT
            0,  // RPC_C_AUTHZ_NONE
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }
}

pub(super) fn collect_wmi_startup(started: Instant) -> WmiStartupCollection {
    let mut diagnostics = Vec::new();
    let mut filters = Vec::new();
    let mut consumers = Vec::new();
    let mut bindings = Vec::new();
    let mut aggregate_units = 0usize;
    let mut status = WindowsStartupStatus::Complete;

    if elapsed(started) {
        diagnostics.push(diagnostic(
            "wmi_scan_deadline_exceeded",
            None,
            "The startup inventory time limit was reached before WMI subscription inventory began.",
        ));
        return WmiStartupCollection {
            source: source_result(
                "wmi_permanent_event_subscriptions",
                WindowsStartupStatus::Partial,
                0,
                diagnostics,
            ),
            filters,
            consumers,
            bindings,
        };
    }

    let init = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    if init.is_err() {
        let mut source = source_result(
            "wmi_permanent_event_subscriptions",
            WindowsStartupStatus::Unavailable,
            0,
            vec![diagnostic_hresult(
                "wmi_com_initialization_failed",
                None,
                "COM initialization for the WMI startup source failed.",
                init,
            )],
        );
        source.location_path = Some(WMI_NAMESPACE.to_owned());
        return WmiStartupCollection {
            source,
            filters,
            consumers,
            bindings,
        };
    }
    let _apartment = ComApartment;
    let locator: IWbemLocator =
        match unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) } {
            Ok(locator) => locator,
            Err(error) => {
                let mut source = source_result(
                    "wmi_permanent_event_subscriptions",
                    WindowsStartupStatus::Unavailable,
                    0,
                    vec![diagnostic_hresult(
                        "wmi_locator_creation_failed",
                        None,
                        "The local WMI locator could not be created.",
                        error.code(),
                    )],
                );
                source.location_path = Some(WMI_NAMESPACE.to_owned());
                return WmiStartupCollection {
                    source,
                    filters,
                    consumers,
                    bindings,
                };
            }
        };
    let namespace = BSTR::from("\\\\.\\ROOT\\subscription");
    let empty = BSTR::new();
    let services = match unsafe {
        locator.ConnectServer(
            &namespace,
            &empty,
            &empty,
            &empty,
            0,
            &empty,
            None::<&windows::Win32::System::Wmi::IWbemContext>,
        )
    } {
        Ok(services) => services,
        Err(error) => {
            let mut source = source_result(
                "wmi_permanent_event_subscriptions",
                map_wmi_error(error.code()),
                0,
                vec![diagnostic_hresult(
                    "wmi_namespace_connect_failed",
                    None,
                    "The local WMI subscription namespace could not be opened under the current token.",
                    error.code(),
                )],
            );
            source.location_path = Some(WMI_NAMESPACE.to_owned());
            return WmiStartupCollection {
                source,
                filters,
                consumers,
                bindings,
            };
        }
    };
    if let Err(error) = set_proxy_security(&services) {
        let mut source = source_result(
            "wmi_permanent_event_subscriptions",
            WindowsStartupStatus::Inaccessible,
            0,
            vec![diagnostic_hresult(
                "wmi_proxy_security_failed",
                None,
                "Explicit WMI proxy security setup failed; no WMI query was issued.",
                error.code(),
            )],
        );
        source.location_path = Some(WMI_NAMESPACE.to_owned());
        return WmiStartupCollection {
            source,
            filters,
            consumers,
            bindings,
        };
    }

    let mut total_rows = 0usize;
    'queries: for (class_name, query) in WMI_QUERIES {
        if elapsed(started) {
            status = WindowsStartupStatus::Partial;
            push_wmi_diagnostic(
                &mut diagnostics,
                diagnostic(
                    "wmi_scan_deadline_exceeded",
                    None,
                    "The startup inventory time limit was reached before all WMI subscription classes were checked.",
                ),
            );
            break;
        }
        let enumerator = match unsafe {
            services.ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(query),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None::<&windows::Win32::System::Wmi::IWbemContext>,
            )
        } {
            Ok(enumerator) => enumerator,
            Err(error) => {
                status = WindowsStartupStatus::Partial;
                push_wmi_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        "wmi_class_query_failed",
                        None,
                        "A fixed WMI subscription-class query failed.",
                        error.code(),
                    ),
                );
                continue;
            }
        };
        if let Err(error) = set_proxy_security(&enumerator) {
            status = WindowsStartupStatus::Partial;
            push_wmi_diagnostic(
                &mut diagnostics,
                diagnostic_hresult(
                    "wmi_proxy_security_failed",
                    None,
                    "Explicit WMI enumerator proxy security setup failed; this class was not read.",
                    error.code(),
                ),
            );
            continue;
        }
        let mut class_count = 0usize;
        loop {
            if elapsed(started) {
                status = WindowsStartupStatus::Partial;
                push_wmi_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "wmi_scan_deadline_exceeded",
                        Some(class_count),
                        "The startup inventory time limit was reached during WMI enumeration.",
                    ),
                );
                break;
            }
            let mut objects = [None];
            let mut returned = 0u32;
            let hr = unsafe { enumerator.Next(WMI_NEXT_TIMEOUT_MS, &mut objects, &mut returned) };
            if returned > 0 && hr.is_err() {
                status = WindowsStartupStatus::Partial;
                push_wmi_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        "wmi_enumeration_failed",
                        Some(class_count),
                        "WMI returned an object together with an enumeration error; the object is retained but the source is partial.",
                        hr,
                    ),
                );
            }
            if returned > 0 && !reserve_wmi_row(&mut total_rows) {
                status = WindowsStartupStatus::Partial;
                push_wmi_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "wmi_total_row_limit_exceeded",
                        None,
                        "The aggregate WMI row limit was reached; remaining query rows were omitted.",
                    ),
                );
                break 'queries;
            }
            if returned == 0 {
                if hr.is_err() {
                    status = WindowsStartupStatus::Partial;
                    push_wmi_diagnostic(
                        &mut diagnostics,
                        diagnostic_hresult(
                            "wmi_enumeration_failed",
                            Some(class_count),
                            "WMI object enumeration failed.",
                            hr,
                        ),
                    );
                    break;
                }
                // WBEM_S_FALSE is normal end-of-enumeration; timeout with S_TIMEDOUT is partial.
                if is_wmi_enumeration_timeout(hr) {
                    status = WindowsStartupStatus::Partial;
                    push_wmi_diagnostic(
                        &mut diagnostics,
                        diagnostic(
                            "wmi_enumeration_timeout",
                            Some(class_count),
                            "WMI returned no object before the bounded enumeration wait expired.",
                        ),
                    );
                }
                break;
            }
            let Some(object) = objects[0].take() else {
                status = WindowsStartupStatus::Partial;
                push_wmi_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "wmi_object_missing",
                        Some(class_count),
                        "WMI reported an object without returning an object interface.",
                    ),
                );
                continue;
            };
            if let Err(error) = set_proxy_security(&object) {
                status = WindowsStartupStatus::Partial;
                push_wmi_diagnostic(
                    &mut diagnostics,
                    diagnostic_hresult(
                        "wmi_proxy_security_failed",
                        Some(class_count),
                        "Explicit WMI object proxy security setup failed; this object was not read.",
                        error.code(),
                    ),
                );
                class_count += 1;
                continue;
            }
            if class_count >= MAX_WMI_ROWS_PER_CLASS {
                status = WindowsStartupStatus::Partial;
                push_wmi_diagnostic(
                    &mut diagnostics,
                    diagnostic(
                        "wmi_row_limit_exceeded",
                        Some(class_count),
                        "The WMI class row limit was reached; additional rows were omitted.",
                    ),
                );
                break;
            }
            let row = match read_wmi_row(&object, class_name, class_count, &mut aggregate_units) {
                Ok(row) => row,
                Err(error) => {
                    status = WindowsStartupStatus::Partial;
                    push_wmi_diagnostic(
                        &mut diagnostics,
                        diagnostic_hresult(
                            property_diagnostic_code(error.property),
                            Some(class_count),
                            "A selected WMI property could not be read, normalized, or kept within bounds; its row was omitted.",
                            error.code,
                        ),
                    );
                    class_count += 1;
                    continue;
                }
            };
            match class_name {
                "__EventFilter" => {
                    if let Some(row) = normalize_filter(row, class_count) {
                        filters.push(row);
                    } else {
                        status = WindowsStartupStatus::Partial;
                        push_wmi_diagnostic(
                            &mut diagnostics,
                            diagnostic(
                                "wmi_filter_required_property_missing",
                                Some(class_count),
                                "A WMI event filter lacked its required object path and was omitted.",
                            ),
                        );
                    }
                }
                "__EventConsumer" => {
                    if let Some(row) = normalize_consumer(row, class_count) {
                        if row.status == WmiConsumerStatus::UnsupportedClass {
                            status = WindowsStartupStatus::Partial;
                            push_wmi_diagnostic(
                                &mut diagnostics,
                                diagnostic(
                                    "wmi_consumer_class_unsupported",
                                    Some(class_count),
                                    "A WMI consumer class was retained by object path but its class-specific fields are unsupported.",
                                ),
                            );
                        }
                        consumers.push(row);
                    } else {
                        status = WindowsStartupStatus::Partial;
                        push_wmi_diagnostic(
                            &mut diagnostics,
                            diagnostic(
                                "wmi_consumer_required_property_missing",
                                Some(class_count),
                                "A WMI event consumer lacked its required object path and was omitted.",
                            ),
                        );
                    }
                }
                "CommandLineEventConsumer" | "ActiveScriptEventConsumer" => {
                    if !merge_consumer_details(&mut consumers, row, class_name, class_count) {
                        status = WindowsStartupStatus::Partial;
                        push_wmi_diagnostic(
                            &mut diagnostics,
                            diagnostic(
                                "wmi_consumer_detail_unmatched",
                                Some(class_count),
                                "A fixed consumer detail row did not exactly match a collected consumer object path; the detail was omitted.",
                            ),
                        );
                    }
                }
                "__FilterToConsumerBinding" => {
                    if let Some(row) = normalize_binding(row, class_count) {
                        bindings.push(row);
                    } else {
                        status = WindowsStartupStatus::Partial;
                        push_wmi_diagnostic(
                            &mut diagnostics,
                            diagnostic(
                                "wmi_binding_required_property_missing",
                                Some(class_count),
                                "A WMI filter-to-consumer binding lacked a required property and was omitted.",
                            ),
                        );
                    }
                }
                _ => unreachable!(),
            }
            class_count += 1;
        }
    }

    resolve_binding_references(&mut bindings, &filters, &consumers);
    if bindings.iter().any(|binding| {
        binding.filter_reference_status == WmiReferenceStatus::Unresolved
            || binding.consumer_reference_status == WmiReferenceStatus::Unresolved
    }) {
        status = WindowsStartupStatus::Partial;
        push_wmi_diagnostic(
            &mut diagnostics,
            diagnostic(
                "wmi_unresolved_binding_reference",
                None,
                "One or more WMI bindings refer to a filter or consumer absent from the collected rows; the reference is retained as unresolved.",
            ),
        );
    }
    let entries_seen = filters.len() + consumers.len() + bindings.len();
    let mut source = source_result(
        "wmi_permanent_event_subscriptions",
        status,
        entries_seen,
        diagnostics,
    );
    source.location_path = Some(WMI_NAMESPACE.to_owned());
    WmiStartupCollection {
        source,
        filters,
        consumers,
        bindings,
    }
}

fn is_wmi_enumeration_timeout(hr: windows::core::HRESULT) -> bool {
    hr.0 == WBEM_S_TIMEDOUT.0
}

#[derive(Default)]
struct WmiRawRow {
    object_path: Option<String>,
    class_name: Option<String>,
    name: Option<String>,
    creator_sid: Option<String>,
    event_namespace: Option<String>,
    query_language: Option<String>,
    query: Option<String>,
    executable_path: Option<String>,
    command_line_template: Option<String>,
    script_file_name: Option<String>,
    script_text: Option<String>,
    filter_reference: Option<String>,
    consumer_reference: Option<String>,
    delivery_qos: Option<String>,
}

type WmiFieldSetter = fn(&mut WmiRawRow) -> &mut Option<String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WmiPropertyReadError {
    property: &'static str,
    code: windows::core::HRESULT,
}

fn read_wmi_row(
    object: &IWbemClassObject,
    class_name: &str,
    index: usize,
    aggregate_units: &mut usize,
) -> Result<WmiRawRow, WmiPropertyReadError> {
    let properties: &[(&str, WmiFieldSetter)] = match class_name {
        "__EventFilter" => &[
            ("__RELPATH", |r| &mut r.object_path),
            ("__CLASS", |r| &mut r.class_name),
            ("Name", |r| &mut r.name),
            ("CreatorSID", |r| &mut r.creator_sid),
            ("EventNamespace", |r| &mut r.event_namespace),
            ("QueryLanguage", |r| &mut r.query_language),
            ("Query", |r| &mut r.query),
        ],
        "__EventConsumer" => &[
            ("__RELPATH", |r| &mut r.object_path),
            ("__CLASS", |r| &mut r.class_name),
            ("CreatorSID", |r| &mut r.creator_sid),
        ],
        "CommandLineEventConsumer" => &[
            ("__RELPATH", |r| &mut r.object_path),
            ("Name", |r| &mut r.name),
            ("ExecutablePath", |r| &mut r.executable_path),
            ("CommandLineTemplate", |r| &mut r.command_line_template),
        ],
        "ActiveScriptEventConsumer" => &[
            ("__RELPATH", |r| &mut r.object_path),
            ("Name", |r| &mut r.name),
            ("ScriptFileName", |r| &mut r.script_file_name),
            ("ScriptText", |r| &mut r.script_text),
        ],
        "__FilterToConsumerBinding" => &[
            ("__RELPATH", |r| &mut r.object_path),
            ("CreatorSID", |r| &mut r.creator_sid),
            ("Filter", |r| &mut r.filter_reference),
            ("Consumer", |r| &mut r.consumer_reference),
            ("DeliveryQoS", |r| &mut r.delivery_qos),
        ],
        _ => unreachable!(),
    };
    let mut row = WmiRawRow::default();
    for (property, target) in properties {
        let mut value = VARIANT::default();
        let result = unsafe {
            object.Get(
                PCWSTR::from_raw(wide_z(property).as_ptr()),
                0,
                &mut value,
                None,
                None,
            )
        };
        if let Err(error) = result {
            unsafe {
                let _ = VariantClear(&mut value);
            }
            return Err(WmiPropertyReadError {
                property,
                code: error.code(),
            });
        }
        let is_null = is_variant_null(unsafe { value.Anonymous.Anonymous.vt.0 });
        if is_null {
            unsafe {
                let _ = VariantClear(&mut value);
            }
            continue;
        }
        let converted = bounded_variant_text(&value, *property == "CreatorSID");
        unsafe {
            let _ = VariantClear(&mut value);
        }
        let text = converted.map_err(|code| WmiPropertyReadError { property, code })?;
        reserve_wmi_text(&text, aggregate_units)
            .map_err(|code| WmiPropertyReadError { property, code })?;
        *target(&mut row) = Some(text);
    }
    let _ = index;
    Ok(row)
}

fn property_diagnostic_code(property: &str) -> &'static str {
    match property {
        "__RELPATH" => "wmi_property_relpath_failed",
        "__CLASS" => "wmi_property_class_failed",
        "Name" => "wmi_property_name_failed",
        "CreatorSID" => "wmi_property_creator_sid_failed",
        "EventNamespace" => "wmi_property_event_namespace_failed",
        "QueryLanguage" => "wmi_property_query_language_failed",
        "Query" => "wmi_property_query_failed",
        "ExecutablePath" => "wmi_property_executable_path_failed",
        "CommandLineTemplate" => "wmi_property_command_line_template_failed",
        "ScriptFileName" => "wmi_property_script_file_name_failed",
        "ScriptText" => "wmi_property_script_text_failed",
        "Filter" => "wmi_property_filter_reference_failed",
        "Consumer" => "wmi_property_consumer_reference_failed",
        "DeliveryQoS" => "wmi_property_delivery_qos_failed",
        _ => "wmi_property_read_failed",
    }
}

fn is_variant_null(vt: u16) -> bool {
    vt == VT_NULL_VARIANT
}

fn reserve_wmi_text(text: &str, aggregate_units: &mut usize) -> Result<(), windows::core::HRESULT> {
    let units = text.encode_utf16().count();
    if units > MAX_WMI_STRING_UNITS
        || aggregate_units.saturating_add(units) > MAX_WMI_AGGREGATE_UNITS
    {
        return Err(windows::core::HRESULT(0x8007_0df0u32 as i32));
    }
    *aggregate_units = aggregate_units.saturating_add(units);
    Ok(())
}

fn reserve_wmi_row(total_rows: &mut usize) -> bool {
    if *total_rows >= MAX_WMI_TOTAL_ROWS {
        return false;
    }
    *total_rows += 1;
    true
}

fn bounded_variant_text(
    value: &VARIANT,
    byte_array_hex: bool,
) -> Result<String, windows::core::HRESULT> {
    let vt = unsafe { value.Anonymous.Anonymous.vt.0 };
    if byte_array_hex && (vt & VT_ARRAY.0) != 0 {
        if vt & 0x0fff != VT_UI1.0 {
            return Err(windows::core::HRESULT(0x8007_0057u32 as i32));
        }
        let array = unsafe { value.Anonymous.Anonymous.Anonymous.parray };
        if array.is_null() || unsafe { SafeArrayGetDim(array) } != 1 {
            return Err(windows::core::HRESULT(0x8007_0057u32 as i32));
        }
        let lower = unsafe { SafeArrayGetLBound(array, 1) }.map_err(|error| error.code())?;
        let upper = unsafe { SafeArrayGetUBound(array, 1) }.map_err(|error| error.code())?;
        let length = if upper < lower {
            0
        } else {
            usize::try_from(i64::from(upper) - i64::from(lower) + 1)
                .map_err(|_| windows::core::HRESULT(0x8007_0057u32 as i32))?
        };
        if length > 128 {
            return Err(windows::core::HRESULT(0x8007_0df0u32 as i32));
        }
        let mut data = std::ptr::null_mut();
        unsafe { SafeArrayAccessData(array, &mut data) }.map_err(|error| error.code())?;
        let bytes = if length == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(data.cast::<u8>(), length) }
        };
        let text = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let _ = unsafe { SafeArrayUnaccessData(array) };
        return Ok(text);
    }
    let mut buffer = vec![0u16; MAX_WMI_STRING_UNITS + 1];
    unsafe { VariantToString(value, &mut buffer) }.map_err(|error| error.code())?;
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    if end > MAX_WMI_STRING_UNITS {
        return Err(windows::core::HRESULT(0x8007_0df0u32 as i32));
    }
    String::from_utf16(&buffer[..end]).map_err(|_| windows::core::HRESULT(0x8007_0570u32 as i32))
}

fn wide_z(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn evidence(class_name: &'static str, index: usize) -> WmiSubscriptionEvidence {
    WmiSubscriptionEvidence {
        source: WMI_SOURCE,
        namespace: WMI_NAMESPACE,
        class_name,
        object_index: index,
    }
}

fn normalize_filter(row: WmiRawRow, index: usize) -> Option<WmiEventFilter> {
    Some(WmiEventFilter {
        object_path: row.object_path?,
        name: row.name,
        creator_sid: row.creator_sid,
        event_namespace: row.event_namespace,
        query_language: row.query_language,
        query: row.query,
        evidence: evidence("__EventFilter", index),
    })
}

fn normalize_consumer(row: WmiRawRow, index: usize) -> Option<WmiEventConsumer> {
    let object_path = row.object_path?;
    let class_name = row.class_name.unwrap_or_else(|| "unknown".to_owned());
    let known = matches!(
        class_name.as_str(),
        "CommandLineEventConsumer"
            | "ActiveScriptEventConsumer"
            | "LogFileEventConsumer"
            | "NTEventLogEventConsumer"
            | "SMTPEventConsumer"
    );
    Some(WmiEventConsumer {
        object_path,
        class_name: class_name.clone(),
        name: row.name,
        creator_sid: row.creator_sid,
        status: if known {
            WmiConsumerStatus::Observed
        } else {
            WmiConsumerStatus::UnsupportedClass
        },
        executable_path: row.executable_path,
        command_line_template: row.command_line_template,
        script_file_name: row.script_file_name,
        script_text: row.script_text,
        evidence: evidence("__EventConsumer", index),
        detail_evidence: None,
    })
}

fn merge_consumer_details(
    consumers: &mut [WmiEventConsumer],
    row: WmiRawRow,
    queried_class: &'static str,
    object_index: usize,
) -> bool {
    let Some(object_path) = row.object_path.as_deref() else {
        return false;
    };
    let Some(consumer) = consumers
        .iter_mut()
        .find(|consumer| consumer.object_path == object_path)
    else {
        return false;
    };
    consumer.name = row.name;
    match queried_class {
        "CommandLineEventConsumer" => {
            consumer.executable_path = row.executable_path;
            consumer.command_line_template = row.command_line_template;
        }
        "ActiveScriptEventConsumer" => {
            consumer.script_file_name = row.script_file_name;
            consumer.script_text = row.script_text;
        }
        _ => return false,
    }
    consumer.detail_evidence = Some(evidence(queried_class, object_index));
    true
}

fn normalize_binding(row: WmiRawRow, index: usize) -> Option<WmiFilterConsumerBinding> {
    Some(WmiFilterConsumerBinding {
        object_path: row.object_path?,
        filter_reference: row.filter_reference?,
        consumer_reference: row.consumer_reference?,
        filter_reference_status: WmiReferenceStatus::Unresolved,
        consumer_reference_status: WmiReferenceStatus::Unresolved,
        creator_sid: row.creator_sid,
        delivery_qos: row.delivery_qos,
        evidence: evidence("__FilterToConsumerBinding", index),
    })
}

fn resolve_binding_references(
    bindings: &mut [WmiFilterConsumerBinding],
    filters: &[WmiEventFilter],
    consumers: &[WmiEventConsumer],
) {
    let filter_paths: BTreeSet<&str> = filters.iter().map(|row| row.object_path.as_str()).collect();
    let consumer_paths: BTreeSet<&str> = consumers
        .iter()
        .map(|row| row.object_path.as_str())
        .collect();
    for binding in bindings {
        binding.filter_reference_status =
            if filter_paths.contains(binding.filter_reference.as_str()) {
                WmiReferenceStatus::Resolved
            } else {
                WmiReferenceStatus::Unresolved
            };
        binding.consumer_reference_status =
            if consumer_paths.contains(binding.consumer_reference.as_str()) {
                WmiReferenceStatus::Resolved
            } else {
                WmiReferenceStatus::Unresolved
            };
    }
}

fn map_wmi_error(hresult: windows::core::HRESULT) -> WindowsStartupStatus {
    match hresult.0 as u32 {
        0x80070005 | 0x80041003 => WindowsStartupStatus::Inaccessible,
        0x8004100e | 0x80041010 | 0x80040154 => WindowsStartupStatus::Unavailable,
        _ => WindowsStartupStatus::Error,
    }
}

fn push_wmi_diagnostic(
    diagnostics: &mut Vec<WindowsStartupDiagnostic>,
    item: WindowsStartupDiagnostic,
) {
    if diagnostics.len() < MAX_WMI_DIAGNOSTICS {
        diagnostics.push(item);
    } else if diagnostics
        .last()
        .is_some_and(|last| last.code != "wmi_diagnostics_limit_exceeded")
    {
        *diagnostics.last_mut().expect("nonempty diagnostic vector") = diagnostic(
            "wmi_diagnostics_limit_exceeded",
            None,
            "Additional WMI startup diagnostics were omitted after the bounded diagnostic limit.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_references_resolve_by_exact_object_path_only() {
        let filter = WmiEventFilter {
            object_path: "__EventFilter.Name=\"f\"".into(),
            name: None,
            creator_sid: None,
            event_namespace: None,
            query_language: None,
            query: None,
            evidence: evidence("__EventFilter", 0),
        };
        let consumer = WmiEventConsumer {
            object_path: "CommandLineEventConsumer.Name=\"c\"".into(),
            class_name: "CommandLineEventConsumer".into(),
            name: None,
            creator_sid: None,
            status: WmiConsumerStatus::Observed,
            executable_path: None,
            command_line_template: None,
            script_file_name: None,
            script_text: None,
            evidence: evidence("__EventConsumer", 0),
            detail_evidence: None,
        };
        let mut bindings = [WmiFilterConsumerBinding {
            object_path: "binding".into(),
            filter_reference: filter.object_path.clone(),
            consumer_reference: "missing".into(),
            filter_reference_status: WmiReferenceStatus::Unresolved,
            consumer_reference_status: WmiReferenceStatus::Unresolved,
            creator_sid: None,
            delivery_qos: None,
            evidence: evidence("__FilterToConsumerBinding", 0),
        }];
        resolve_binding_references(&mut bindings, &[filter], &[consumer]);
        assert_eq!(
            bindings[0].filter_reference_status,
            WmiReferenceStatus::Resolved
        );
        assert_eq!(
            bindings[0].consumer_reference_status,
            WmiReferenceStatus::Unresolved
        );
    }

    #[test]
    fn unknown_consumer_classes_are_retained_as_unsupported() {
        let consumer = normalize_consumer(
            WmiRawRow {
                object_path: Some("CustomConsumer.Name=\"x\"".into()),
                class_name: Some("CustomConsumer".into()),
                ..Default::default()
            },
            0,
        )
        .unwrap();
        assert_eq!(consumer.status, WmiConsumerStatus::UnsupportedClass);
        assert_eq!(consumer.object_path, "CustomConsumer.Name=\"x\"");
    }

    #[test]
    fn known_consumer_text_is_retained_inertly() {
        let consumer = normalize_consumer(
            WmiRawRow {
                object_path: Some("CommandLineEventConsumer.Name=\"sample\"".into()),
                class_name: Some("CommandLineEventConsumer".into()),
                command_line_template: Some("untrusted argument text".into()),
                ..Default::default()
            },
            4,
        )
        .unwrap();
        assert_eq!(consumer.status, WmiConsumerStatus::Observed);
        assert_eq!(
            consumer.command_line_template.as_deref(),
            Some("untrusted argument text")
        );
        assert_eq!(consumer.evidence.object_index, 4);
    }

    #[test]
    fn concrete_consumer_details_merge_only_on_exact_object_path() {
        let mut consumers = [WmiEventConsumer {
            object_path: "CommandLineEventConsumer.Name=\"same\"".into(),
            class_name: "CommandLineEventConsumer".into(),
            name: None,
            creator_sid: Some("0101000000000005".into()),
            status: WmiConsumerStatus::Observed,
            executable_path: None,
            command_line_template: None,
            script_file_name: None,
            script_text: None,
            evidence: evidence("__EventConsumer", 2),
            detail_evidence: None,
        }];
        assert!(merge_consumer_details(
            &mut consumers,
            WmiRawRow {
                object_path: Some("CommandLineEventConsumer.Name=\"same\"".into()),
                name: Some("same".into()),
                command_line_template: Some("inert command data".into()),
                ..Default::default()
            },
            "CommandLineEventConsumer",
            5
        ));
        assert_eq!(
            consumers[0].command_line_template.as_deref(),
            Some("inert command data")
        );
        assert_eq!(consumers[0].evidence.class_name, "__EventConsumer");
        assert_eq!(
            consumers[0].detail_evidence.as_ref().unwrap().class_name,
            "CommandLineEventConsumer"
        );
        assert_eq!(
            consumers[0].detail_evidence.as_ref().unwrap().object_index,
            5
        );
        assert!(!merge_consumer_details(
            &mut consumers,
            WmiRawRow {
                object_path: Some("CommandLineEventConsumer.Name=\"different\"".into()),
                command_line_template: Some("must not be joined".into()),
                ..Default::default()
            },
            "CommandLineEventConsumer",
            6
        ));
        assert_eq!(
            consumers[0].command_line_template.as_deref(),
            Some("inert command data")
        );
    }

    #[test]
    fn string_budgets_are_fixed_and_diagnostic_count_is_capped() {
        assert_eq!(MAX_WMI_STRING_UNITS, 16_384);
        assert_eq!(MAX_WMI_AGGREGATE_UNITS, 2 * 1024 * 1024);
        assert_eq!(MAX_WMI_TOTAL_ROWS, 8_192);
        let mut diagnostics = (0..MAX_WMI_DIAGNOSTICS)
            .map(|_| diagnostic("item", None, "item"))
            .collect::<Vec<_>>();
        push_wmi_diagnostic(&mut diagnostics, diagnostic("extra", None, "extra"));
        assert_eq!(diagnostics.len(), MAX_WMI_DIAGNOSTICS);
        assert_eq!(
            diagnostics.last().unwrap().code,
            "wmi_diagnostics_limit_exceeded"
        );
        let mut aggregate = 0;
        assert!(reserve_wmi_text(&"x".repeat(MAX_WMI_STRING_UNITS), &mut aggregate).is_ok());
        assert_eq!(aggregate, MAX_WMI_STRING_UNITS);
        assert!(reserve_wmi_text("x", &mut aggregate).is_ok());
        assert!(reserve_wmi_text(&"x".repeat(MAX_WMI_AGGREGATE_UNITS), &mut aggregate).is_err());
        assert!(reserve_wmi_text(&"😀".repeat(MAX_WMI_STRING_UNITS / 2 + 1), &mut 0).is_err());
        let mut rows = 0;
        for _ in 0..MAX_WMI_TOTAL_ROWS {
            assert!(reserve_wmi_row(&mut rows));
        }
        assert!(!reserve_wmi_row(&mut rows));
    }

    #[test]
    fn enumeration_timeout_is_distinct_from_normal_end_of_sequence() {
        assert_eq!(WBEM_S_TIMEDOUT.0 as u32, 0x0004_0004);
        assert!(is_wmi_enumeration_timeout(windows::core::HRESULT(
            WBEM_S_TIMEDOUT.0
        )));
        assert!(!is_wmi_enumeration_timeout(windows::core::HRESULT(
            windows::Win32::System::Wmi::WBEM_S_FALSE.0
        )));
    }

    #[test]
    fn property_failures_are_identifiable_and_only_variant_null_is_absent() {
        assert_eq!(
            property_diagnostic_code("CommandLineTemplate"),
            "wmi_property_command_line_template_failed"
        );
        assert_eq!(
            property_diagnostic_code("Query"),
            "wmi_property_query_failed"
        );
        assert!(is_variant_null(VT_NULL_VARIANT));
        assert!(!is_variant_null(0));
        assert!(!is_variant_null(VT_NULL_VARIANT + 1));
    }
}
