//! Strict, bounded TDH decoding for documented classic kernel process events.

use serde::Serialize;
use std::mem::{offset_of, size_of};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::{
    DecodingSourceWbem, EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER,
    EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_TYPE_DC_END, EVENT_TRACE_TYPE_DC_START,
    EVENT_TRACE_TYPE_END, EVENT_TRACE_TYPE_START, PROPERTY_DATA_DESCRIPTOR, ProcessGuid,
    PropertyHasTags, PropertyParamCount, PropertyParamFixedCount, PropertyParamFixedLength,
    PropertyParamLength, PropertyStruct, TDH_INTYPE_POINTER, TDH_INTYPE_UINT32,
    TDH_INTYPE_UNICODESTRING, TDH_OUTTYPE_HEXINT32, TDH_OUTTYPE_HEXINT64, TDH_OUTTYPE_NULL,
    TDH_OUTTYPE_STRING, TRACE_EVENT_INFO, TdhGetEventInformation, TdhGetProperty,
    TdhGetPropertySize,
};

const MAX_TDH_METADATA_BYTES: usize = 256 * 1024;
const MAX_TDH_PROPERTIES: usize = 128;
const MAX_PROPERTY_BYTES: usize = 64 * 1024;
const MAX_IMAGE_FILE_NAME_UTF16_UNITS: usize = 32 * 1024;
const SUPPORTED_EVENT_VERSIONS: std::ops::RangeInclusive<u8> = 0..=4;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeStatus {
    Decoded,
    UnsupportedVersion,
    UnsupportedOpcode,
    AmbiguousPointerSize,
    SchemaUnavailable,
    SchemaMismatch,
    MalformedPayload,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DecodedProcessPayload {
    pub status: DecodeStatus,
    pub schema_name: Option<&'static str>,
    pub schema_version: Option<u8>,
    pub pointer_size_bytes: Option<u8>,
    pub process_id: Option<u32>,
    pub parent_process_id: Option<u32>,
    pub image_file_name: Option<String>,
    pub diagnostic: Option<&'static str>,
}

impl DecodedProcessPayload {
    pub(super) fn undecoded(status: DecodeStatus, diagnostic: &'static str) -> Self {
        Self {
            status,
            schema_name: None,
            schema_version: None,
            pointer_size_bytes: None,
            process_id: None,
            parent_process_id: None,
            image_file_name: None,
            diagnostic: Some(diagnostic),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PropertyMetadata {
    name: String,
    input_type: u16,
    output_type: u16,
    flags: i32,
    count: u16,
    length: u16,
    top_level: bool,
}

#[derive(Clone)]
struct EventMetadata {
    event_guid: windows_sys::core::GUID,
    event_id: u16,
    event_version: u8,
    event_opcode: u8,
    decoding_source: i32,
    properties: Vec<PropertyMetadata>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PropertyBytes {
    name: &'static str,
    bytes: Vec<u8>,
}

/// Decode an EVENT_RECORD using its registered MOF schema. TDH reads properties
/// while the native event is live; raw UserData bytes are retained separately.
pub(super) fn decode_event_payload(event: &EVENT_RECORD) -> DecodedProcessPayload {
    let descriptor = &event.EventHeader.EventDescriptor;
    if !guid_equal(event.EventHeader.ProviderId, ProcessGuid) {
        return DecodedProcessPayload::undecoded(
            DecodeStatus::SchemaMismatch,
            "unexpected_process_event_guid",
        );
    }
    if let Err(status) = validate_event_key(descriptor.Version, descriptor.Opcode) {
        let diagnostic = match status {
            DecodeStatus::UnsupportedVersion => "unsupported_process_event_version",
            _ => "unsupported_process_event_opcode",
        };
        return DecodedProcessPayload::undecoded(status, diagnostic);
    }
    let pointer_size = match pointer_size_from_header(event.EventHeader.Flags) {
        Some(value) => value,
        None => {
            return DecodedProcessPayload::undecoded(
                DecodeStatus::AmbiguousPointerSize,
                "event_header_pointer_width_is_ambiguous",
            );
        }
    };
    if usize::from(event.UserDataLength) > MAX_PROPERTY_BYTES
        || (event.UserDataLength != 0 && event.UserData.is_null())
    {
        return DecodedProcessPayload::undecoded(
            DecodeStatus::MalformedPayload,
            "invalid_or_oversized_event_payload",
        );
    }

    let metadata = match query_event_metadata(event) {
        Ok(value) => value,
        Err(TdhFailure::Unavailable) => {
            return DecodedProcessPayload::undecoded(
                DecodeStatus::SchemaUnavailable,
                "tdh_schema_unavailable",
            );
        }
        Err(TdhFailure::Malformed) => {
            return DecodedProcessPayload::undecoded(
                DecodeStatus::SchemaMismatch,
                "tdh_metadata_invalid_or_unexpected",
            );
        }
    };
    if validate_metadata(
        &metadata,
        descriptor.Id,
        descriptor.Version,
        descriptor.Opcode,
    )
    .is_err()
    {
        return DecodedProcessPayload::undecoded(
            DecodeStatus::SchemaMismatch,
            "tdh_schema_does_not_match_process_event",
        );
    }
    if validate_selected_properties(&metadata, pointer_size).is_err() {
        return DecodedProcessPayload::undecoded(
            DecodeStatus::SchemaMismatch,
            "process_property_schema_is_unexpected",
        );
    }

    let process_id = match query_property(event, "ProcessId") {
        Ok(bytes) => bytes,
        Err(_) => {
            return DecodedProcessPayload::undecoded(
                DecodeStatus::MalformedPayload,
                "process_id_property_unavailable",
            );
        }
    };
    let parent_process_id = match query_property(event, "ParentId") {
        Ok(bytes) => bytes,
        Err(_) => {
            return DecodedProcessPayload::undecoded(
                DecodeStatus::MalformedPayload,
                "parent_process_id_property_unavailable",
            );
        }
    };
    let image_file_name = match query_property(event, "ImageFileName") {
        Ok(bytes) => bytes,
        Err(_) => {
            return DecodedProcessPayload::undecoded(
                DecodeStatus::MalformedPayload,
                "image_file_name_property_unavailable",
            );
        }
    };
    decode_validated_properties(
        &metadata,
        pointer_size,
        &[
            PropertyBytes {
                name: "ProcessId",
                bytes: process_id,
            },
            PropertyBytes {
                name: "ParentId",
                bytes: parent_process_id,
            },
            PropertyBytes {
                name: "ImageFileName",
                bytes: image_file_name,
            },
        ],
    )
}

#[derive(Clone, Copy, Debug)]
enum TdhFailure {
    Unavailable,
    Malformed,
}

fn query_event_metadata(event: &EVENT_RECORD) -> Result<EventMetadata, TdhFailure> {
    let mut required = 0_u32;
    let first = unsafe {
        TdhGetEventInformation(
            event,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut required,
        )
    };
    if first != ERROR_INSUFFICIENT_BUFFER || required == 0 {
        return Err(TdhFailure::Unavailable);
    }
    let requested = usize::try_from(required).map_err(|_| TdhFailure::Malformed)?;
    if requested > MAX_TDH_METADATA_BYTES {
        return Err(TdhFailure::Malformed);
    }
    let words = requested.div_ceil(size_of::<u64>());
    let mut buffer = Vec::<u64>::new();
    buffer
        .try_reserve_exact(words)
        .map_err(|_| TdhFailure::Malformed)?;
    buffer.resize(words, 0);
    let allocated_bytes = words
        .checked_mul(size_of::<u64>())
        .ok_or(TdhFailure::Malformed)?;
    let mut returned = u32::try_from(allocated_bytes).map_err(|_| TdhFailure::Malformed)?;
    let result = unsafe {
        TdhGetEventInformation(
            event,
            0,
            std::ptr::null(),
            buffer.as_mut_ptr().cast::<TRACE_EVENT_INFO>(),
            &mut returned,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(TdhFailure::Unavailable);
    }
    let returned_bytes = usize::try_from(returned).map_err(|_| TdhFailure::Malformed)?;
    if returned_bytes > allocated_bytes || returned_bytes > MAX_TDH_METADATA_BYTES {
        return Err(TdhFailure::Malformed);
    }
    let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned_bytes) };
    metadata_from_bytes(bytes)
}

fn metadata_from_bytes(bytes: &[u8]) -> Result<EventMetadata, TdhFailure> {
    let base_size = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
    if bytes.len() < base_size || bytes.len() < size_of::<TRACE_EVENT_INFO>() {
        return Err(TdhFailure::Malformed);
    }
    let info = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<TRACE_EVENT_INFO>()) };
    let property_count = usize::try_from(info.PropertyCount).map_err(|_| TdhFailure::Malformed)?;
    let top_level_count =
        usize::try_from(info.TopLevelPropertyCount).map_err(|_| TdhFailure::Malformed)?;
    if property_count == 0
        || property_count > MAX_TDH_PROPERTIES
        || top_level_count > property_count
    {
        return Err(TdhFailure::Malformed);
    }
    let props_bytes = property_count
        .checked_mul(size_of::<EVENT_PROPERTY_INFO>())
        .and_then(|size| base_size.checked_add(size))
        .ok_or(TdhFailure::Malformed)?;
    if props_bytes > bytes.len() {
        return Err(TdhFailure::Malformed);
    }
    let mut properties = Vec::new();
    properties
        .try_reserve_exact(property_count)
        .map_err(|_| TdhFailure::Malformed)?;
    for index in 0..property_count {
        let offset = base_size
            .checked_add(
                index
                    .checked_mul(size_of::<EVENT_PROPERTY_INFO>())
                    .ok_or(TdhFailure::Malformed)?,
            )
            .ok_or(TdhFailure::Malformed)?;
        let property = unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<EVENT_PROPERTY_INFO>())
        };
        let name = metadata_string(bytes, property.NameOffset, props_bytes)?;
        let (input_type, output_type) = unsafe {
            let value = property.Anonymous1.nonStructType;
            (value.InType, value.OutType)
        };
        properties.push(PropertyMetadata {
            name,
            input_type,
            output_type,
            flags: property.Flags,
            count: unsafe { property.Anonymous2.count },
            length: unsafe { property.Anonymous3.length },
            top_level: index < top_level_count,
        });
    }
    Ok(EventMetadata {
        event_guid: info.EventGuid,
        event_id: info.EventDescriptor.Id,
        event_version: info.EventDescriptor.Version,
        event_opcode: info.EventDescriptor.Opcode,
        decoding_source: info.DecodingSource,
        properties,
    })
}

fn metadata_string(bytes: &[u8], offset: u32, properties_end: usize) -> Result<String, TdhFailure> {
    let offset = usize::try_from(offset).map_err(|_| TdhFailure::Malformed)?;
    let base_size = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
    if offset < base_size
        || offset < properties_end
        || offset >= bytes.len()
        || offset % size_of::<u16>() != 0
    {
        return Err(TdhFailure::Malformed);
    }
    let rest = &bytes[offset..];
    let mut units = Vec::new();
    for pair in rest.chunks_exact(2).take(257) {
        let unit = u16::from_ne_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return String::from_utf16(&units).map_err(|_| TdhFailure::Malformed);
        }
        if units.len() >= 256 {
            return Err(TdhFailure::Malformed);
        }
        units.push(unit);
    }
    Err(TdhFailure::Malformed)
}

fn query_property(event: &EVENT_RECORD, name: &str) -> Result<Vec<u8>, TdhFailure> {
    let mut wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let descriptor = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: wide_name.as_mut_ptr() as usize as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut required = 0_u32;
    let size_result =
        unsafe { TdhGetPropertySize(event, 0, std::ptr::null(), 1, &descriptor, &mut required) };
    if size_result != ERROR_SUCCESS || required == 0 {
        return Err(TdhFailure::Malformed);
    }
    let size = usize::try_from(required).map_err(|_| TdhFailure::Malformed)?;
    if size > MAX_PROPERTY_BYTES {
        return Err(TdhFailure::Malformed);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| TdhFailure::Malformed)?;
    bytes.resize(size, 0);
    let result = unsafe {
        TdhGetProperty(
            event,
            0,
            std::ptr::null(),
            1,
            &descriptor,
            required,
            bytes.as_mut_ptr(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(TdhFailure::Malformed);
    }
    Ok(bytes)
}

fn validate_metadata(
    metadata: &EventMetadata,
    event_id: u16,
    event_version: u8,
    event_opcode: u8,
) -> Result<(), ()> {
    if !guid_equal(metadata.event_guid, ProcessGuid)
        || metadata.event_id != event_id
        || metadata.event_version != event_version
        || metadata.event_opcode != event_opcode
        || metadata.decoding_source != DecodingSourceWbem
    {
        return Err(());
    }
    Ok(())
}

fn validate_event_key(version: u8, opcode: u8) -> Result<(), DecodeStatus> {
    if !SUPPORTED_EVENT_VERSIONS.contains(&version) {
        return Err(DecodeStatus::UnsupportedVersion);
    }
    if !matches!(
        u32::from(opcode),
        EVENT_TRACE_TYPE_START
            | EVENT_TRACE_TYPE_END
            | EVENT_TRACE_TYPE_DC_START
            | EVENT_TRACE_TYPE_DC_END
    ) {
        return Err(DecodeStatus::UnsupportedOpcode);
    }
    Ok(())
}

fn validate_selected_properties(metadata: &EventMetadata, pointer_size: usize) -> Result<(), ()> {
    let process_id = find_property(metadata, "ProcessId")?;
    let parent_id = find_property(metadata, "ParentId")?;
    let image = find_property(metadata, "ImageFileName")?;
    validate_id_property(process_id, pointer_size)?;
    validate_id_property(parent_id, pointer_size)?;
    if !property_flags_supported(image.flags)
        || image.count != 1
        || image.length != 0
        || image.input_type != TDH_INTYPE_UNICODESTRING as u16
        || (image.output_type != TDH_OUTTYPE_NULL as u16
            && image.output_type != TDH_OUTTYPE_STRING as u16)
    {
        return Err(());
    }
    Ok(())
}

fn find_property<'a>(metadata: &'a EventMetadata, name: &str) -> Result<&'a PropertyMetadata, ()> {
    let mut matching = metadata
        .properties
        .iter()
        .filter(|property| property.name == name && property.top_level);
    let property = matching.next().ok_or(())?;
    if matching.next().is_some() {
        return Err(());
    }
    Ok(property)
}

fn validate_id_property(property: &PropertyMetadata, pointer_size: usize) -> Result<(), ()> {
    if !property_flags_supported(property.flags) || property.count != 1 {
        return Err(());
    }
    let valid_output = property.output_type == TDH_OUTTYPE_NULL as u16
        || property.output_type == TDH_OUTTYPE_HEXINT32 as u16
        || property.output_type == TDH_OUTTYPE_HEXINT64 as u16;
    if !valid_output {
        return Err(());
    }
    match property.input_type {
        value if value == TDH_INTYPE_UINT32 as u16 => {
            if property.length != 4 {
                return Err(());
            }
        }
        value if value == TDH_INTYPE_POINTER as u16 => {
            if property.length != 0 && usize::from(property.length) != pointer_size {
                return Err(());
            }
        }
        _ => return Err(()),
    }
    Ok(())
}

fn property_flags_supported(flags: i32) -> bool {
    flags
        & !(PropertyHasTags
            | PropertyStruct
            | PropertyParamCount
            | PropertyParamLength
            | PropertyParamFixedCount
            | PropertyParamFixedLength)
        == 0
        && flags
            & (PropertyStruct
                | PropertyParamCount
                | PropertyParamLength
                | PropertyParamFixedCount
                | PropertyParamFixedLength)
            == 0
}

fn pointer_size_from_header(flags: u16) -> Option<usize> {
    let flags = u32::from(flags);
    match (
        flags & EVENT_HEADER_FLAG_32_BIT_HEADER != 0,
        flags & EVENT_HEADER_FLAG_64_BIT_HEADER != 0,
    ) {
        (true, false) => Some(4),
        (false, true) => Some(8),
        _ => None,
    }
}

fn decode_validated_properties(
    metadata: &EventMetadata,
    pointer_size: usize,
    values: &[PropertyBytes],
) -> DecodedProcessPayload {
    let property_value = |name: &'static str| {
        let mut found = values.iter().filter(|property| property.name == name);
        let value = found.next().ok_or(())?;
        if found.next().is_some() {
            return Err(());
        }
        Ok(value.bytes.as_slice())
    };
    let process_id = property_value("ProcessId")
        .and_then(|value| decode_id(find_property(metadata, "ProcessId")?, pointer_size, value));
    let parent_id = property_value("ParentId")
        .and_then(|value| decode_id(find_property(metadata, "ParentId")?, pointer_size, value));
    let image = property_value("ImageFileName").and_then(decode_image_file_name);
    match (process_id, parent_id, image) {
        (Ok(process_id), Ok(parent_process_id), Ok(image_file_name)) => DecodedProcessPayload {
            status: DecodeStatus::Decoded,
            schema_name: Some("windows.kernel_process_typegroup1"),
            schema_version: Some(metadata.event_version),
            pointer_size_bytes: Some(pointer_size as u8),
            process_id: Some(process_id),
            parent_process_id: Some(parent_process_id),
            image_file_name: Some(image_file_name),
            diagnostic: None,
        },
        _ => DecodedProcessPayload::undecoded(
            DecodeStatus::MalformedPayload,
            "process_payload_property_value_is_invalid",
        ),
    }
}

fn decode_id(property: &PropertyMetadata, pointer_size: usize, bytes: &[u8]) -> Result<u32, ()> {
    match property.input_type {
        value if value == TDH_INTYPE_UINT32 as u16 => {
            let value: [u8; 4] = bytes.try_into().map_err(|_| ())?;
            Ok(u32::from_le_bytes(value))
        }
        value if value == TDH_INTYPE_POINTER as u16 && pointer_size == 4 => {
            let value: [u8; 4] = bytes.try_into().map_err(|_| ())?;
            Ok(u32::from_le_bytes(value))
        }
        value if value == TDH_INTYPE_POINTER as u16 && pointer_size == 8 => {
            let value: [u8; 8] = bytes.try_into().map_err(|_| ())?;
            u32::try_from(u64::from_le_bytes(value)).map_err(|_| ())
        }
        _ => Err(()),
    }
}

fn decode_image_file_name(bytes: &[u8]) -> Result<String, ()> {
    if bytes.len() < 2
        || bytes.len() > MAX_PROPERTY_BYTES
        || bytes.len() % 2 != 0
        || bytes.len() / 2 > MAX_IMAGE_FILE_NAME_UTF16_UNITS
    {
        return Err(());
    }
    let mut units = Vec::new();
    units.try_reserve_exact(bytes.len() / 2).map_err(|_| ())?;
    for pair in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err(());
    }
    String::from_utf16(&units[..units.len() - 1]).map_err(|_| ())
}

fn guid_equal(left: windows_sys::core::GUID, right: windows_sys::core::GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Diagnostics::Etw::TDH_INTYPE_UINT64;

    fn property(name: &str, input_type: i32, output_type: i32, length: u16) -> PropertyMetadata {
        PropertyMetadata {
            name: name.to_owned(),
            input_type: input_type as u16,
            output_type: output_type as u16,
            flags: 0,
            count: 1,
            length,
            top_level: true,
        }
    }

    fn schema(version: u8, pointer_ids: bool) -> EventMetadata {
        let id_type = if pointer_ids {
            TDH_INTYPE_POINTER
        } else {
            TDH_INTYPE_UINT32
        };
        let id_length = if pointer_ids { 0 } else { 4 };
        EventMetadata {
            event_guid: ProcessGuid,
            event_id: 0,
            event_version: version,
            event_opcode: EVENT_TRACE_TYPE_START as u8,
            decoding_source: DecodingSourceWbem,
            properties: vec![
                property("ProcessId", id_type, TDH_OUTTYPE_HEXINT32, id_length),
                property("ParentId", id_type, TDH_OUTTYPE_HEXINT32, id_length),
                property(
                    "ImageFileName",
                    TDH_INTYPE_UNICODESTRING,
                    TDH_OUTTYPE_NULL,
                    0,
                ),
            ],
        }
    }

    fn metadata_fixture_bytes(metadata: &EventMetadata) -> Vec<u8> {
        use windows_sys::Win32::System::Diagnostics::Etw::{
            EVENT_PROPERTY_INFO_0_0, TRACE_EVENT_INFO,
        };
        let base_size = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
        let props_size = metadata.properties.len() * size_of::<EVENT_PROPERTY_INFO>();
        let mut strings = Vec::new();
        let mut name_offsets = Vec::new();
        for property in &metadata.properties {
            name_offsets.push(base_size + props_size + strings.len() * size_of::<u16>());
            strings.extend(property.name.encode_utf16().chain(std::iter::once(0)));
        }
        let total_size = base_size + props_size + strings.len() * size_of::<u16>();
        let mut bytes = vec![0_u8; total_size];
        let info = TRACE_EVENT_INFO {
            EventGuid: metadata.event_guid,
            EventDescriptor: windows_sys::Win32::System::Diagnostics::Etw::EVENT_DESCRIPTOR {
                Id: metadata.event_id,
                Version: metadata.event_version,
                Opcode: metadata.event_opcode,
                ..Default::default()
            },
            DecodingSource: metadata.decoding_source,
            PropertyCount: metadata.properties.len() as u32,
            TopLevelPropertyCount: metadata
                .properties
                .iter()
                .filter(|property| property.top_level)
                .count() as u32,
            ..Default::default()
        };
        unsafe {
            std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<TRACE_EVENT_INFO>(), info);
        }
        for (index, property) in metadata.properties.iter().enumerate() {
            let mut info = EVENT_PROPERTY_INFO {
                NameOffset: name_offsets[index] as u32,
                ..Default::default()
            };
            info.Anonymous1.nonStructType = EVENT_PROPERTY_INFO_0_0 {
                InType: property.input_type,
                OutType: property.output_type,
                MapNameOffset: 0,
            };
            info.Anonymous2.count = property.count;
            info.Anonymous3.length = property.length;
            let offset = base_size + index * size_of::<EVENT_PROPERTY_INFO>();
            unsafe {
                std::ptr::write_unaligned(
                    bytes.as_mut_ptr().add(offset).cast::<EVENT_PROPERTY_INFO>(),
                    info,
                );
            }
        }
        let mut offset = base_size + props_size;
        for unit in strings {
            bytes[offset..offset + 2].copy_from_slice(&unit.to_ne_bytes());
            offset += 2;
        }
        bytes
    }

    fn values(process_id: Vec<u8>, parent_id: Vec<u8>) -> Vec<PropertyBytes> {
        vec![
            PropertyBytes {
                name: "ProcessId",
                bytes: process_id,
            },
            PropertyBytes {
                name: "ParentId",
                bytes: parent_id,
            },
            PropertyBytes {
                name: "ImageFileName",
                bytes: vec![b'C', 0, b':', 0, b'\\', 0, b'x', 0, 0, 0],
            },
        ]
    }

    #[test]
    fn documented_process_v0_pointer_fields_decode_without_header_pid_substitution() {
        let metadata = schema(0, true);
        assert!(validate_metadata(&metadata, 0, 0, EVENT_TRACE_TYPE_START as u8).is_ok());
        assert!(validate_selected_properties(&metadata, 4).is_ok());
        let decoded = decode_validated_properties(
            &metadata,
            4,
            &values(42_u32.to_le_bytes().to_vec(), 7_u32.to_le_bytes().to_vec()),
        );
        assert_eq!(decoded.status, DecodeStatus::Decoded);
        assert_eq!(decoded.process_id, Some(42));
        assert_eq!(decoded.parent_process_id, Some(7));
        assert_eq!(decoded.image_file_name.as_deref(), Some("C:\\x"));
    }

    #[test]
    fn validated_process_v1_through_v4_uint32_fields_decode() {
        for version in [1, 2, 3, 4] {
            let metadata = schema(version, false);
            let decoded = decode_validated_properties(
                &metadata,
                8,
                &values(42_u32.to_le_bytes().to_vec(), 7_u32.to_le_bytes().to_vec()),
            );
            assert_eq!(decoded.status, DecodeStatus::Decoded);
            assert_eq!(decoded.schema_version, Some(version));
            assert_eq!(decoded.process_id, Some(42));
            assert_eq!(decoded.parent_process_id, Some(7));
        }
    }

    #[test]
    fn unknown_version_opcode_metadata_types_and_duplicate_properties_fail_closed() {
        let mut metadata = schema(5, false);
        assert!(validate_metadata(&metadata, 0, 5, EVENT_TRACE_TYPE_START as u8).is_ok());
        assert!(!SUPPORTED_EVENT_VERSIONS.contains(&metadata.event_version));
        assert_eq!(
            validate_event_key(5, EVENT_TRACE_TYPE_START as u8),
            Err(DecodeStatus::UnsupportedVersion)
        );
        assert_eq!(
            validate_event_key(2, 39),
            Err(DecodeStatus::UnsupportedOpcode)
        );
        assert!(validate_event_key(2, EVENT_TRACE_TYPE_DC_START as u8).is_ok());
        assert!(validate_event_key(2, EVENT_TRACE_TYPE_DC_END as u8).is_ok());

        metadata.event_guid = windows_sys::core::GUID::from_u128(0);
        assert!(validate_metadata(&metadata, 0, 2, EVENT_TRACE_TYPE_START as u8).is_err());

        let mut metadata = schema(2, false);
        metadata.properties[0].input_type = TDH_INTYPE_UINT64 as u16;
        assert!(validate_selected_properties(&metadata, 8).is_err());
        metadata.properties[0].input_type = TDH_INTYPE_UINT32 as u16;
        metadata.properties.push(metadata.properties[0].clone());
        assert!(find_property(&metadata, "ProcessId").is_err());
    }

    #[test]
    fn tdh_metadata_buffer_requires_bounded_property_array_and_valid_names() {
        let expected = schema(2, false);
        let bytes = metadata_fixture_bytes(&expected);
        let parsed = metadata_from_bytes(&bytes).unwrap();
        assert!(validate_metadata(&parsed, 0, 2, EVENT_TRACE_TYPE_START as u8).is_ok());
        assert!(validate_selected_properties(&parsed, 8).is_ok());

        let mut truncated = bytes.clone();
        truncated.truncate(offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray));
        assert!(metadata_from_bytes(&truncated).is_err());

        let mut invalid_name = bytes;
        let info =
            unsafe { std::ptr::read_unaligned(invalid_name.as_ptr().cast::<TRACE_EVENT_INFO>()) };
        let _ = info;
        let name_offset_location = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray)
            + offset_of!(EVENT_PROPERTY_INFO, NameOffset);
        invalid_name[name_offset_location..name_offset_location + 4]
            .copy_from_slice(&u32::MAX.to_ne_bytes());
        assert!(metadata_from_bytes(&invalid_name).is_err());
    }

    #[test]
    fn pointer_width_requires_one_unambiguous_header_flag() {
        assert_eq!(
            pointer_size_from_header(EVENT_HEADER_FLAG_32_BIT_HEADER as u16),
            Some(4)
        );
        assert_eq!(
            pointer_size_from_header(EVENT_HEADER_FLAG_64_BIT_HEADER as u16),
            Some(8)
        );
        assert_eq!(pointer_size_from_header(0), None);
        assert_eq!(
            pointer_size_from_header(
                (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER) as u16
            ),
            None
        );
    }

    #[test]
    fn malformed_or_oversized_pid_and_image_values_are_rejected() {
        let pointer = property("ProcessId", TDH_INTYPE_POINTER, TDH_OUTTYPE_HEXINT32, 0);
        assert!(decode_id(&pointer, 4, &[1, 2, 3]).is_err());
        assert!(decode_id(&pointer, 8, &u64::MAX.to_le_bytes()).is_err());
        assert!(decode_image_file_name(&[b'x', 0]).is_err());
        assert!(decode_image_file_name(&[0, 0, b'x', 0]).is_err());
        assert!(decode_image_file_name(&vec![0; MAX_PROPERTY_BYTES + 2]).is_err());
        assert!(decode_image_file_name(&[0x00, 0xD8, 0, 0]).is_err());
    }
}
