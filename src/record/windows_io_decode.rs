//! Strict decoding for selected classic Windows kernel FileIo, TcpIp, and UdpIp events.
//!
//! Payload layouts and event types follow the published Microsoft MOF schemas:
//! <https://learn.microsoft.com/en-us/windows/win32/etw/fileio>
//! <https://learn.microsoft.com/en-us/windows/win32/etw/tcpip>
//! <https://learn.microsoft.com/en-us/windows/win32/etw/udpip>
//! <https://learn.microsoft.com/en-us/windows/win32/etw/diskio>
//! <https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1>
//! <https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup3>
//! This decoder intentionally accepts only event descriptor ID 0, provider
//! schema version 2, and the listed event opcodes. It does not infer that a
//! requested file operation completed successfully.

use serde::Serialize;

const FILE_IO_GUID: &str = "90cbdc39-4a3e-11d1-84f4-0000f80464e3";
const TCP_IP_GUID: &str = "9a280ac0-c8e0-11d1-84e2-00c04fb998a2";
const UDP_IP_GUID: &str = "bf3a50c5-a9c9-4988-a005-2df0b7c80f80";
const DISK_IO_GUID: &str = "3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c";
const CLASSIC_EVENT_ID: u16 = 0;
const CLASSIC_NETWORK_FILE_SCHEMA_VERSION: u8 = 2;
// The published DiskIo class has no EventVersion qualifier; classic MOF
// providers use version 0 for its initial schema.
const DISK_IO_SCHEMA_VERSION: u8 = 0;
const MAX_EVENT_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_PATH_UTF16_UNITS: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PointerWidth {
    Bits32,
    Bits64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DecodeStatus {
    Decoded,
    UnsupportedProvider,
    UnsupportedEvent,
    UnsupportedVersion,
    AmbiguousPointerWidth,
    MalformedPayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct DecodeResult {
    pub status: DecodeStatus,
    pub diagnostic: Option<&'static str>,
    pub observation: Option<DecodedObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct DecodedObservation {
    pub schema: &'static str,
    pub schema_version: u8,
    pub activity: Activity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "observation")]
pub(super) enum Activity {
    File(FileObservation),
    Network(NetworkObservation),
    Disk(DiskObservation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum FileOperation {
    Name,
    CreateName,
    DeleteName,
    RundownName,
    CreateRequest,
    ReadRequest,
    WriteRequest,
    SetInformationRequest,
    DeleteRequest,
    RenameRequest,
    QueryInformationRequest,
    FileSystemControlRequest,
    Cleanup,
    Close,
    FlushRequest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct FileObservation {
    pub operation: FileOperation,
    pub thread_id: Option<u64>,
    pub file_object: u64,
    pub file_key: Option<u64>,
    pub path: Option<String>,
    pub requested_bytes: Option<u32>,
    pub file_offset: Option<u64>,
    pub create_options: Option<u32>,
    pub file_attributes: Option<u32>,
    pub share_access: Option<u32>,
    pub information_class: Option<u32>,
    pub extra_info: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Transport {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum NetworkOperation {
    Connect,
    Accept,
    Disconnect,
    Send,
    Receive,
    Retransmit,
    Reconnect,
    TcpCopy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct NetworkObservation {
    pub transport: Transport,
    pub operation: NetworkOperation,
    /// The `PID` field from the documented provider payload, not header PID.
    pub payload_process_id: u32,
    pub source_address: IpAddress,
    pub destination_address: IpAddress,
    pub source_port: u16,
    pub destination_port: u16,
    pub packet_size: u32,
    pub sequence_number: u32,
    pub connection_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DiskOperation {
    Read,
    Write,
    FlushBuffers,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) struct DiskObservation {
    pub operation: DiskOperation,
    pub disk_number: u32,
    pub irp_flags: u32,
    pub transfer_size_bytes: Option<u32>,
    pub byte_offset: Option<i64>,
    pub file_object: Option<u64>,
    pub irp: u64,
    /// Provider-reported duration in QPC tick units; it is not a success result.
    pub high_resolution_response_time_ticks: u64,
    /// Absent from supported older schema variants; not inferred from header TID.
    pub issuing_thread_id: Option<u32>,
}

/// Decode a classic event payload after the ETW callback has copied its bytes.
/// `provider_guid` may be formatted with or without braces and in either hex
/// case. `event_id`, version, and opcode are the EVENT_DESCRIPTOR fields.
pub(super) fn decode_classic_event(
    provider_guid: &str,
    event_id: u16,
    version: u8,
    opcode: u8,
    pointer_width: Option<PointerWidth>,
    payload: &[u8],
) -> DecodeResult {
    if payload.len() > MAX_EVENT_PAYLOAD_BYTES {
        return failed(
            DecodeStatus::MalformedPayload,
            "event_payload_exceeds_limit",
        );
    }
    let normalized = normalize_guid(provider_guid);
    let provider = if normalized.is_some_and(|guid| guid.eq_ignore_ascii_case(FILE_IO_GUID)) {
        Provider::FileIo
    } else if normalized.is_some_and(|guid| guid.eq_ignore_ascii_case(TCP_IP_GUID)) {
        Provider::TcpIp
    } else if normalized.is_some_and(|guid| guid.eq_ignore_ascii_case(UDP_IP_GUID)) {
        Provider::UdpIp
    } else if normalized.is_some_and(|guid| guid.eq_ignore_ascii_case(DISK_IO_GUID)) {
        Provider::DiskIo
    } else {
        return failed(
            DecodeStatus::UnsupportedProvider,
            "classic_io_provider_not_supported",
        );
    };
    if event_id != CLASSIC_EVENT_ID {
        return failed(
            DecodeStatus::UnsupportedEvent,
            "classic_event_id_not_supported",
        );
    }
    let expected_version = if matches!(provider, Provider::DiskIo) {
        DISK_IO_SCHEMA_VERSION
    } else {
        CLASSIC_NETWORK_FILE_SCHEMA_VERSION
    };
    if version != expected_version {
        return failed(
            DecodeStatus::UnsupportedVersion,
            "classic_provider_schema_version_not_supported",
        );
    }
    let Some(width) = pointer_width else {
        return failed(
            DecodeStatus::AmbiguousPointerWidth,
            "event_pointer_width_is_ambiguous",
        );
    };
    let parsed = match provider {
        Provider::FileIo => decode_file(opcode, width, payload),
        Provider::TcpIp => decode_network(opcode, Transport::Tcp, width, payload),
        Provider::UdpIp => decode_network(opcode, Transport::Udp, width, payload),
        Provider::DiskIo => decode_disk(opcode, width, payload),
    };
    match parsed {
        Ok((schema, activity)) => DecodeResult {
            status: DecodeStatus::Decoded,
            diagnostic: None,
            observation: Some(DecodedObservation {
                schema,
                schema_version: version,
                activity,
            }),
        },
        Err(ParseError::Unsupported) => failed(
            DecodeStatus::UnsupportedEvent,
            "classic_event_opcode_not_supported",
        ),
        Err(ParseError::Malformed) => failed(
            DecodeStatus::MalformedPayload,
            "classic_event_payload_does_not_match_schema",
        ),
    }
}

#[derive(Clone, Copy)]
enum Provider {
    FileIo,
    TcpIp,
    UdpIp,
    DiskIo,
}

#[derive(Clone, Copy)]
enum ParseError {
    Unsupported,
    Malformed,
}

fn failed(status: DecodeStatus, diagnostic: &'static str) -> DecodeResult {
    DecodeResult {
        status,
        diagnostic: Some(diagnostic),
        observation: None,
    }
}

fn normalize_guid(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    let without_braces = trimmed
        .strip_prefix('{')
        .and_then(|inner| inner.strip_suffix('}'))
        .unwrap_or(trimmed);
    if without_braces.len() != 36
        || !without_braces
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
    {
        return None;
    }
    Some(without_braces)
}

fn decode_file(
    opcode: u8,
    width: PointerWidth,
    payload: &[u8],
) -> Result<(&'static str, Activity), ParseError> {
    let mut cursor = Cursor::new(payload);
    let observation = match opcode {
        0 | 32 | 35 | 36 => {
            let file_object = cursor.pointer(width)?;
            let path = cursor.wide_z()?;
            let operation = match opcode {
                0 => FileOperation::Name,
                32 => FileOperation::CreateName,
                35 => FileOperation::DeleteName,
                _ => FileOperation::RundownName,
            };
            FileObservation {
                operation,
                thread_id: None,
                file_object,
                file_key: None,
                path: Some(path),
                requested_bytes: None,
                file_offset: None,
                create_options: None,
                file_attributes: None,
                share_access: None,
                information_class: None,
                extra_info: None,
            }
        }
        64 => {
            let _irp = cursor.pointer(width)?;
            let thread_id = cursor.pointer(width)?;
            let file_object = cursor.pointer(width)?;
            let create_options = cursor.u32()?;
            let file_attributes = cursor.u32()?;
            let share_access = cursor.u32()?;
            let path = cursor.wide_z()?;
            FileObservation {
                operation: FileOperation::CreateRequest,
                thread_id: Some(thread_id),
                file_object,
                file_key: None,
                path: Some(path),
                requested_bytes: None,
                file_offset: None,
                create_options: Some(create_options),
                file_attributes: Some(file_attributes),
                share_access: Some(share_access),
                information_class: None,
                extra_info: None,
            }
        }
        65 | 66 | 73 => {
            let _irp = cursor.pointer(width)?;
            let thread_id = cursor.pointer(width)?;
            let file_object = cursor.pointer(width)?;
            let file_key = cursor.pointer(width)?;
            FileObservation {
                operation: match opcode {
                    65 => FileOperation::Cleanup,
                    66 => FileOperation::Close,
                    _ => FileOperation::FlushRequest,
                },
                thread_id: Some(thread_id),
                file_object,
                file_key: Some(file_key),
                path: None,
                requested_bytes: None,
                file_offset: None,
                create_options: None,
                file_attributes: None,
                share_access: None,
                information_class: None,
                extra_info: None,
            }
        }
        67 | 68 => {
            let offset = cursor.u64()?;
            let _irp = cursor.pointer(width)?;
            let thread_id = cursor.pointer(width)?;
            let file_object = cursor.pointer(width)?;
            let file_key = cursor.pointer(width)?;
            let requested_bytes = cursor.u32()?;
            let _io_flags = cursor.u32()?;
            FileObservation {
                operation: if opcode == 67 {
                    FileOperation::ReadRequest
                } else {
                    FileOperation::WriteRequest
                },
                thread_id: Some(thread_id),
                file_object,
                file_key: Some(file_key),
                path: None,
                requested_bytes: Some(requested_bytes),
                file_offset: Some(offset),
                create_options: None,
                file_attributes: None,
                share_access: None,
                information_class: None,
                extra_info: None,
            }
        }
        69 | 70 | 71 | 74 | 75 => {
            let _irp = cursor.pointer(width)?;
            let thread_id = cursor.pointer(width)?;
            let file_object = cursor.pointer(width)?;
            let file_key = cursor.pointer(width)?;
            let extra_info = cursor.pointer(width)?;
            let information_class = cursor.u32()?;
            FileObservation {
                operation: match opcode {
                    69 => FileOperation::SetInformationRequest,
                    70 => FileOperation::DeleteRequest,
                    71 => FileOperation::RenameRequest,
                    74 => FileOperation::QueryInformationRequest,
                    _ => FileOperation::FileSystemControlRequest,
                },
                thread_id: Some(thread_id),
                file_object,
                file_key: Some(file_key),
                path: None,
                requested_bytes: None,
                file_offset: None,
                create_options: None,
                file_attributes: None,
                share_access: None,
                information_class: Some(information_class),
                extra_info: Some(extra_info),
            }
        }
        _ => return Err(ParseError::Unsupported),
    };
    if !cursor.is_empty() {
        return Err(ParseError::Malformed);
    }
    Ok(("windows.kernel_file_io", Activity::File(observation)))
}

fn decode_network(
    opcode: u8,
    transport: Transport,
    width: PointerWidth,
    payload: &[u8],
) -> Result<(&'static str, Activity), ParseError> {
    let (operation, address_width, schema) = match (transport, opcode) {
        (Transport::Tcp, 10) => (NetworkOperation::Send, 4, "windows.kernel_tcp_ipv4_send"),
        (Transport::Tcp, 11 | 13 | 14 | 16 | 18) => (
            match opcode {
                11 => NetworkOperation::Receive,
                13 => NetworkOperation::Disconnect,
                14 => NetworkOperation::Retransmit,
                16 => NetworkOperation::Reconnect,
                _ => NetworkOperation::TcpCopy,
            },
            4,
            "windows.kernel_tcp_ipv4_typegroup1",
        ),
        (Transport::Tcp, 12 | 15) => (
            if opcode == 12 {
                NetworkOperation::Connect
            } else {
                NetworkOperation::Accept
            },
            4,
            "windows.kernel_tcp_ipv4_typegroup2",
        ),
        (Transport::Tcp, 26) => (NetworkOperation::Send, 16, "windows.kernel_tcp_ipv6_send"),
        (Transport::Tcp, 27 | 29 | 30 | 32 | 34) => (
            match opcode {
                27 => NetworkOperation::Receive,
                29 => NetworkOperation::Disconnect,
                30 => NetworkOperation::Retransmit,
                32 => NetworkOperation::Reconnect,
                _ => NetworkOperation::TcpCopy,
            },
            16,
            "windows.kernel_tcp_ipv6_typegroup3",
        ),
        (Transport::Tcp, 28 | 31) => (
            if opcode == 28 {
                NetworkOperation::Connect
            } else {
                NetworkOperation::Accept
            },
            16,
            "windows.kernel_tcp_ipv6_typegroup4",
        ),
        (Transport::Udp, 10 | 11) => (
            if opcode == 10 {
                NetworkOperation::Send
            } else {
                NetworkOperation::Receive
            },
            4,
            "windows.kernel_udp_ipv4_typegroup1",
        ),
        (Transport::Udp, 26 | 27) => (
            if opcode == 26 {
                NetworkOperation::Send
            } else {
                NetworkOperation::Receive
            },
            16,
            "windows.kernel_udp_ipv6_typegroup2",
        ),
        _ => return Err(ParseError::Unsupported),
    };

    let mut cursor = Cursor::new(payload);
    let payload_process_id = cursor.u32()?;
    let packet_size = cursor.u32()?;
    let destination_address = cursor.address(address_width)?;
    let source_address = cursor.address(address_width)?;
    let destination_port = cursor.port()?;
    let source_port = cursor.port()?;
    let (sequence_number, connection_id) =
        if schema.ends_with("typegroup1") || schema.ends_with("typegroup3") {
            (cursor.u32()?, cursor.pointer(width)?)
        } else if schema.ends_with("typegroup2") || schema.ends_with("typegroup4") {
            if transport == Transport::Tcp {
                // MSS, SACK, timestamp and window-scale options; receive window;
                // signed receive/send window scales; sequence number; connection ID.
                let _mss = cursor.u16()?;
                let _sack_option = cursor.u16()?;
                let _timestamp_option = cursor.u16()?;
                let _window_scale_option = cursor.u16()?;
                let _receive_window = cursor.u32()?;
                let _receive_window_scale = cursor.i16()?;
                let _send_window_scale = cursor.i16()?;
                (cursor.u32()?, cursor.pointer(width)?)
            } else {
                (cursor.u32()?, cursor.pointer(width)?)
            }
        } else if schema.ends_with("send") {
            let _start_time = cursor.u32()?;
            let _end_time = cursor.u32()?;
            (cursor.u32()?, cursor.pointer(width)?)
        } else {
            return Err(ParseError::Unsupported);
        };
    if !cursor.is_empty() {
        return Err(ParseError::Malformed);
    }
    Ok((
        schema,
        Activity::Network(NetworkObservation {
            transport,
            operation,
            payload_process_id,
            source_address,
            destination_address,
            source_port,
            destination_port,
            packet_size,
            sequence_number,
            connection_id,
        }),
    ))
}

fn decode_disk(
    opcode: u8,
    width: PointerWidth,
    payload: &[u8],
) -> Result<(&'static str, Activity), ParseError> {
    let mut cursor = Cursor::new(payload);
    let disk_number = cursor.u32()?;
    let irp_flags = cursor.u32()?;
    let observation = match opcode {
        10 | 11 => {
            let transfer_size_bytes = cursor.u32()?;
            let _reserved = cursor.u32()?;
            let byte_offset = cursor.i64()?;
            let file_object = cursor.pointer(width)?;
            let irp = cursor.pointer(width)?;
            let high_resolution_response_time_ticks = cursor.u64()?;
            // Current supported Windows builds use the latest published
            // DiskIo_TypeGroup1 layout, which includes IssuingThreadId.
            let issuing_thread_id = cursor.u32()?;
            DiskObservation {
                operation: if opcode == 10 {
                    DiskOperation::Read
                } else {
                    DiskOperation::Write
                },
                disk_number,
                irp_flags,
                transfer_size_bytes: Some(transfer_size_bytes),
                byte_offset: Some(byte_offset),
                file_object: Some(file_object),
                irp,
                high_resolution_response_time_ticks,
                issuing_thread_id: Some(issuing_thread_id),
            }
        }
        14 => {
            let high_resolution_response_time_ticks = cursor.u64()?;
            let irp = cursor.pointer(width)?;
            // The documented provider does not emit this property on older
            // Windows releases. Those layouts are not guessed or accepted.
            let issuing_thread_id = cursor.u32()?;
            DiskObservation {
                operation: DiskOperation::FlushBuffers,
                disk_number,
                irp_flags,
                transfer_size_bytes: None,
                byte_offset: None,
                file_object: None,
                irp,
                high_resolution_response_time_ticks,
                issuing_thread_id: Some(issuing_thread_id),
            }
        }
        _ => return Err(ParseError::Unsupported),
    };
    if !cursor.is_empty() {
        return Err(ParseError::Malformed);
    }
    Ok(("windows.kernel_disk_io", Activity::Disk(observation)))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ParseError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ParseError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ParseError::Malformed)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn i16(&mut self) -> Result<i16, ParseError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ParseError::Malformed)?;
        Ok(i16::from_le_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, ParseError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ParseError::Malformed)?;
        Ok(i64::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ParseError::Malformed)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, ParseError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ParseError::Malformed)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn pointer(&mut self, width: PointerWidth) -> Result<u64, ParseError> {
        match width {
            PointerWidth::Bits32 => Ok(u64::from(self.u32()?)),
            PointerWidth::Bits64 => self.u64(),
        }
    }

    fn port(&mut self) -> Result<u16, ParseError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ParseError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn address(&mut self, length: usize) -> Result<IpAddress, ParseError> {
        match length {
            4 => Ok(IpAddress::V4(
                self.take(4)?
                    .try_into()
                    .map_err(|_| ParseError::Malformed)?,
            )),
            16 => Ok(IpAddress::V6(
                self.take(16)?
                    .try_into()
                    .map_err(|_| ParseError::Malformed)?,
            )),
            _ => Err(ParseError::Malformed),
        }
    }

    fn wide_z(&mut self) -> Result<String, ParseError> {
        let remaining = &self.bytes[self.offset..];
        if remaining.len() < 2 || remaining.len() % 2 != 0 {
            return Err(ParseError::Malformed);
        }
        let max_bytes = MAX_PATH_UTF16_UNITS
            .checked_mul(2)
            .ok_or(ParseError::Malformed)?;
        if remaining.len() > max_bytes {
            return Err(ParseError::Malformed);
        }
        let mut units = Vec::new();
        units
            .try_reserve_exact(remaining.len() / 2)
            .map_err(|_| ParseError::Malformed)?;
        let mut terminator = None;
        for (index, pair) in remaining.chunks_exact(2).enumerate() {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            if unit == 0 {
                terminator = Some(index);
                if index + 1 != remaining.len() / 2 {
                    return Err(ParseError::Malformed);
                }
                break;
            }
            units.push(unit);
        }
        let Some(_) = terminator else {
            return Err(ParseError::Malformed);
        };
        let path = String::from_utf16(&units).map_err(|_| ParseError::Malformed)?;
        self.offset = self.bytes.len();
        Ok(path)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pointer(bytes: &mut Vec<u8>, value: u64, width: PointerWidth) {
        match width {
            PointerWidth::Bits32 => bytes.extend_from_slice(&(value as u32).to_le_bytes()),
            PointerWidth::Bits64 => bytes.extend_from_slice(&value.to_le_bytes()),
        }
    }

    fn u32v(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64v(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn i64v(bytes: &mut Vec<u8>, value: i64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn disk_payload(opcode: u8, width: PointerWidth) -> Vec<u8> {
        let mut bytes = Vec::new();
        u32v(&mut bytes, 2); // DiskNumber
        u32v(&mut bytes, 0x10); // IrpFlags
        match opcode {
            10 | 11 => {
                u32v(&mut bytes, 4096); // TransferSize
                u32v(&mut bytes, 0); // Reserved
                i64v(&mut bytes, 8192); // ByteOffset
                pointer(&mut bytes, 0x1010, width); // FileObject
                pointer(&mut bytes, 0x2020, width); // Irp
                u64v(&mut bytes, 55); // HighResResponseTime
                u32v(&mut bytes, 33); // IssuingThreadId
            }
            14 => {
                u64v(&mut bytes, 77); // HighResResponseTime
                pointer(&mut bytes, 0x3030, width); // Irp
                u32v(&mut bytes, 34); // IssuingThreadId
            }
            _ => unreachable!("test only builds documented DiskIo opcodes"),
        }
        bytes
    }

    fn file_name_payload(width: PointerWidth, path: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        pointer(&mut bytes, 0x1234, width);
        for unit in path.encode_utf16().chain(std::iter::once(0)) {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn network_payload_v4(width: PointerWidth, tcp_connect: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        u32v(&mut bytes, 4242); // PID
        u32v(&mut bytes, 12); // size
        bytes.extend_from_slice(&[127, 0, 0, 1]); // daddr
        bytes.extend_from_slice(&[127, 0, 0, 1]); // saddr
        bytes.extend_from_slice(&443_u16.to_be_bytes());
        bytes.extend_from_slice(&50_000_u16.to_be_bytes());
        if tcp_connect {
            for value in [1460_u16, 1, 1, 7] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            u32v(&mut bytes, 65_535);
            bytes.extend_from_slice(&1_i16.to_le_bytes());
            bytes.extend_from_slice(&2_i16.to_le_bytes());
            u32v(&mut bytes, 99);
            pointer(&mut bytes, 0x7788, width);
        } else {
            u32v(&mut bytes, 99);
            pointer(&mut bytes, 0x7788, width);
        }
        bytes
    }

    fn network_payload_v6_udp(width: PointerWidth) -> Vec<u8> {
        let mut bytes = Vec::new();
        u32v(&mut bytes, 1000);
        u32v(&mut bytes, 9);
        bytes.extend_from_slice(&[0; 15]);
        bytes.push(1);
        bytes.extend_from_slice(&[0; 15]);
        bytes.push(1);
        bytes.extend_from_slice(&53_u16.to_be_bytes());
        bytes.extend_from_slice(&42_000_u16.to_be_bytes());
        u32v(&mut bytes, 7);
        pointer(&mut bytes, 0x123456, width);
        bytes
    }

    fn network_payload(opcode: u8, transport: Transport, width: PointerWidth) -> Vec<u8> {
        if transport == Transport::Udp && matches!(opcode, 26 | 27) {
            return network_payload_v6_udp(width);
        }
        let mut bytes = Vec::new();
        u32v(&mut bytes, 7);
        u32v(&mut bytes, 8);
        let ipv6 = matches!((transport, opcode), (Transport::Tcp, 26..=34));
        let address_width = if ipv6 { 16 } else { 4 };
        bytes.resize(bytes.len() + address_width * 2, 0x7f);
        bytes.extend_from_slice(&80_u16.to_be_bytes());
        bytes.extend_from_slice(&50_000_u16.to_be_bytes());
        if transport == Transport::Tcp && matches!(opcode, 12 | 15 | 28 | 31) {
            for value in [1460_u16, 1, 1, 1] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            u32v(&mut bytes, 4096);
            bytes.extend_from_slice(&1_i16.to_le_bytes());
            bytes.extend_from_slice(&1_i16.to_le_bytes());
            u32v(&mut bytes, 9);
            pointer(&mut bytes, 10, width);
        } else if transport == Transport::Tcp && matches!(opcode, 10 | 26) {
            u32v(&mut bytes, 100);
            u32v(&mut bytes, 101);
            u32v(&mut bytes, 9);
            pointer(&mut bytes, 10, width);
        } else {
            u32v(&mut bytes, 9);
            pointer(&mut bytes, 10, width);
        }
        bytes
    }

    fn file_payload(opcode: u8, width: PointerWidth) -> Vec<u8> {
        let mut bytes = Vec::new();
        match opcode {
            0 | 32 | 35 | 36 => {
                pointer(&mut bytes, 11, width);
                for unit in "C:\\fixture".encode_utf16().chain(std::iter::once(0)) {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
            }
            64 => {
                for value in [1, 2, 3] {
                    pointer(&mut bytes, value, width);
                }
                for value in [4, 5, 6] {
                    u32v(&mut bytes, value);
                }
                for unit in "C:\\fixture".encode_utf16().chain(std::iter::once(0)) {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
            }
            65 | 66 | 73 => {
                for value in [1, 2, 3, 4] {
                    pointer(&mut bytes, value, width);
                }
            }
            67 | 68 => {
                u64v(&mut bytes, 100);
                for value in [1, 2, 3, 4] {
                    pointer(&mut bytes, value, width);
                }
                u32v(&mut bytes, 12);
                u32v(&mut bytes, 0);
            }
            69 | 70 | 71 | 74 | 75 => {
                for value in [1, 2, 3, 4, 5] {
                    pointer(&mut bytes, value, width);
                }
                u32v(&mut bytes, 6);
            }
            _ => unreachable!("test only builds documented file event opcodes"),
        }
        bytes
    }

    fn decode(provider: &str, opcode: u8, payload: &[u8]) -> DecodeResult {
        decode_classic_event(provider, 0, 2, opcode, Some(PointerWidth::Bits64), payload)
    }

    #[test]
    fn file_name_event_decodes_bounded_utf16_for_32_and_64_bit_headers() {
        for width in [PointerWidth::Bits32, PointerWidth::Bits64] {
            let payload = file_name_payload(width, "C:\\audit\\fixture.txt");
            let result = decode_classic_event(
                &format!("{{{FILE_IO_GUID}}}"),
                0,
                2,
                0,
                Some(width),
                &payload,
            );
            assert_eq!(result.status, DecodeStatus::Decoded);
            let Some(DecodedObservation {
                activity: Activity::File(file),
                ..
            }) = result.observation
            else {
                panic!("expected file observation");
            };
            assert_eq!(file.file_object, 0x1234);
            assert_eq!(file.path.as_deref(), Some("C:\\audit\\fixture.txt"));
            assert_eq!(file.operation, FileOperation::Name);
        }
    }

    #[test]
    fn file_create_and_read_events_decode_only_requested_facts() {
        let width = PointerWidth::Bits64;
        let mut create = Vec::new();
        pointer(&mut create, 1, width);
        pointer(&mut create, 41, width);
        pointer(&mut create, 2, width);
        u32v(&mut create, 0x100);
        u32v(&mut create, 0x20);
        u32v(&mut create, 3);
        for unit in "C:\\audit\\x".encode_utf16().chain(std::iter::once(0)) {
            create.extend_from_slice(&unit.to_le_bytes());
        }
        let result = decode(FILE_IO_GUID, 64, &create);
        assert_eq!(result.status, DecodeStatus::Decoded);
        let Some(DecodedObservation {
            activity: Activity::File(file),
            ..
        }) = result.observation
        else {
            panic!("expected file observation");
        };
        assert_eq!(file.thread_id, Some(41));
        assert_eq!(file.create_options, Some(0x100));
        assert_eq!(file.path.as_deref(), Some("C:\\audit\\x"));

        let mut read = Vec::new();
        u64v(&mut read, 128);
        for value in [9, 41, 2, 3] {
            pointer(&mut read, value, width);
        }
        u32v(&mut read, 512);
        u32v(&mut read, 0);
        let result = decode(FILE_IO_GUID, 67, &read);
        let Some(DecodedObservation {
            activity: Activity::File(file),
            ..
        }) = result.observation
        else {
            panic!("expected file observation");
        };
        assert_eq!(file.operation, FileOperation::ReadRequest);
        assert_eq!(file.file_offset, Some(128));
        assert_eq!(file.requested_bytes, Some(512));
    }

    #[test]
    fn tcp_ipv4_connect_and_udp_ipv6_receive_decode_payload_identity() {
        let tcp = decode(
            TCP_IP_GUID,
            12,
            &network_payload_v4(PointerWidth::Bits64, true),
        );
        assert_eq!(tcp.status, DecodeStatus::Decoded);
        let Some(DecodedObservation {
            activity: Activity::Network(network),
            ..
        }) = tcp.observation
        else {
            panic!("expected network observation");
        };
        assert_eq!(network.transport, Transport::Tcp);
        assert_eq!(network.operation, NetworkOperation::Connect);
        assert_eq!(network.payload_process_id, 4242);
        assert_eq!(network.destination_port, 443);

        let udp = decode(
            UDP_IP_GUID,
            27,
            &network_payload_v6_udp(PointerWidth::Bits64),
        );
        assert_eq!(udp.status, DecodeStatus::Decoded);
        let Some(DecodedObservation {
            activity: Activity::Network(network),
            ..
        }) = udp.observation
        else {
            panic!("expected network observation");
        };
        assert_eq!(network.transport, Transport::Udp);
        assert_eq!(network.operation, NetworkOperation::Receive);
        assert_eq!(network.source_port, 42_000);
        assert_eq!(
            network.destination_address,
            IpAddress::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
    }

    #[test]
    fn disk_read_write_and_flush_decode_exact_32_and_64_bit_layouts() {
        for width in [PointerWidth::Bits32, PointerWidth::Bits64] {
            for (opcode, expected_operation) in [
                (10, DiskOperation::Read),
                (11, DiskOperation::Write),
                (14, DiskOperation::FlushBuffers),
            ] {
                let payload = disk_payload(opcode, width);
                let result = decode_classic_event(
                    DISK_IO_GUID,
                    0,
                    DISK_IO_SCHEMA_VERSION,
                    opcode,
                    Some(width),
                    &payload,
                );
                assert_eq!(
                    result.status,
                    DecodeStatus::Decoded,
                    "DiskIo opcode {opcode}"
                );
                let Some(DecodedObservation {
                    schema: "windows.kernel_disk_io",
                    activity: Activity::Disk(disk),
                    ..
                }) = result.observation
                else {
                    panic!("expected disk observation");
                };
                assert_eq!(disk.operation, expected_operation);
                assert_eq!(disk.disk_number, 2);
                assert_eq!(disk.irp_flags, 0x10);
                assert_eq!(
                    disk.issuing_thread_id,
                    Some(if opcode == 14 { 34 } else { 33 })
                );
                if opcode == 14 {
                    assert_eq!(disk.transfer_size_bytes, None);
                    assert_eq!(disk.high_resolution_response_time_ticks, 77);
                    assert_eq!(disk.irp, 0x3030);
                } else {
                    assert_eq!(disk.transfer_size_bytes, Some(4096));
                    assert_eq!(disk.byte_offset, Some(8192));
                    assert_eq!(disk.file_object, Some(0x1010));
                    assert_eq!(disk.irp, 0x2020);
                    assert_eq!(disk.high_resolution_response_time_ticks, 55);
                }
            }
        }
    }

    #[test]
    fn disk_unlisted_types_versions_and_malformed_payloads_fail_closed() {
        let payload = disk_payload(10, PointerWidth::Bits64);
        let wrong_version =
            decode_classic_event(DISK_IO_GUID, 0, 1, 10, Some(PointerWidth::Bits64), &payload);
        assert_eq!(wrong_version.status, DecodeStatus::UnsupportedVersion);
        let wrong_opcode = decode_classic_event(
            DISK_IO_GUID,
            0,
            DISK_IO_SCHEMA_VERSION,
            12,
            Some(PointerWidth::Bits64),
            &payload,
        );
        assert_eq!(wrong_opcode.status, DecodeStatus::UnsupportedEvent);
        let truncated = decode_classic_event(
            DISK_IO_GUID,
            0,
            DISK_IO_SCHEMA_VERSION,
            10,
            Some(PointerWidth::Bits64),
            &payload[..payload.len() - 1],
        );
        assert_eq!(truncated.status, DecodeStatus::MalformedPayload);
        let mut trailing = payload;
        trailing.push(0);
        let trailing = decode_classic_event(
            DISK_IO_GUID,
            0,
            DISK_IO_SCHEMA_VERSION,
            10,
            Some(PointerWidth::Bits64),
            &trailing,
        );
        assert_eq!(trailing.status, DecodeStatus::MalformedPayload);
    }

    #[test]
    fn accepts_only_the_explicitly_supported_file_tcp_and_udp_event_opcodes() {
        for width in [PointerWidth::Bits32, PointerWidth::Bits64] {
            for opcode in [0, 32, 35, 36, 64, 65, 66, 67, 68, 69, 70, 71, 73, 74, 75] {
                let payload = file_payload(opcode, width);
                let result =
                    decode_classic_event(FILE_IO_GUID, 0, 2, opcode, Some(width), &payload);
                assert_eq!(result.status, DecodeStatus::Decoded, "file opcode {opcode}");
            }
            for opcode in [
                10, 11, 12, 13, 14, 15, 16, 18, 26, 27, 28, 29, 30, 31, 32, 34,
            ] {
                let payload = network_payload(opcode, Transport::Tcp, width);
                let result = decode_classic_event(TCP_IP_GUID, 0, 2, opcode, Some(width), &payload);
                assert_eq!(result.status, DecodeStatus::Decoded, "TCP opcode {opcode}");
            }
            for opcode in [10, 11, 26, 27] {
                let payload = network_payload(opcode, Transport::Udp, width);
                let result = decode_classic_event(UDP_IP_GUID, 0, 2, opcode, Some(width), &payload);
                assert_eq!(result.status, DecodeStatus::Decoded, "UDP opcode {opcode}");
            }
        }
        for (provider, opcode) in [
            (FILE_IO_GUID, 1),
            (TCP_IP_GUID, 17),
            (TCP_IP_GUID, 19),
            (UDP_IP_GUID, 12),
            (UDP_IP_GUID, 28),
        ] {
            assert_eq!(
                decode(provider, opcode, &[]).status,
                DecodeStatus::UnsupportedEvent
            );
        }
    }

    #[test]
    fn unknown_provider_descriptor_and_versions_fail_closed() {
        let payload = file_name_payload(PointerWidth::Bits64, "C:\\x");
        let unknown_provider = decode("11111111-2222-3333-4444-555555555555", 0, &payload);
        assert_eq!(unknown_provider.status, DecodeStatus::UnsupportedProvider);
        let wrong_id =
            decode_classic_event(FILE_IO_GUID, 1, 2, 0, Some(PointerWidth::Bits64), &payload);
        assert_eq!(wrong_id.status, DecodeStatus::UnsupportedEvent);
        let wrong_version =
            decode_classic_event(FILE_IO_GUID, 0, 1, 0, Some(PointerWidth::Bits64), &payload);
        assert_eq!(wrong_version.status, DecodeStatus::UnsupportedVersion);
        let wrong_opcode = decode(FILE_IO_GUID, 99, &payload);
        assert_eq!(wrong_opcode.status, DecodeStatus::UnsupportedEvent);
        let no_width = decode_classic_event(FILE_IO_GUID, 0, 2, 0, None, &payload);
        assert_eq!(no_width.status, DecodeStatus::AmbiguousPointerWidth);
    }

    #[test]
    fn malformed_truncated_oversized_and_trailing_data_fail_closed() {
        let truncated = decode(FILE_IO_GUID, 0, &[0; 4]);
        assert_eq!(truncated.status, DecodeStatus::MalformedPayload);
        let no_terminator = decode(FILE_IO_GUID, 0, &[0x34, 0x12, b'A', 0]);
        assert_eq!(no_terminator.status, DecodeStatus::MalformedPayload);
        let mut trailing = file_name_payload(PointerWidth::Bits64, "C:\\x");
        trailing.push(0);
        let trailing = decode(FILE_IO_GUID, 0, &trailing);
        assert_eq!(trailing.status, DecodeStatus::MalformedPayload);
        let oversized = vec![0; MAX_EVENT_PAYLOAD_BYTES + 1];
        assert_eq!(
            decode(FILE_IO_GUID, 0, &oversized).status,
            DecodeStatus::MalformedPayload
        );
        let malformed_network = decode(TCP_IP_GUID, 12, &[0; 16]);
        assert_eq!(malformed_network.status, DecodeStatus::MalformedPayload);
    }
}
