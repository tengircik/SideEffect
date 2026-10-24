pub const MAX_TRACE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_RECORDS: usize = 100_000;
pub const MAX_JSON_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    pub max_trace_bytes: usize,
    pub max_record_bytes: usize,
    pub max_records: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_trace_bytes: MAX_TRACE_BYTES,
            max_record_bytes: MAX_RECORD_BYTES,
            max_records: MAX_RECORDS,
        }
    }
}
