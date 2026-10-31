#![no_main]

use libfuzzer_sys::fuzz_target;
use sideeffect::limits::ParseLimits;
use sideeffect::trace::strace::parse_trace_bytes;

// Keep the harness cheap and independent of the larger production limits. The
// parser itself still receives arbitrary bytes, including invalid UTF-8.
const FUZZ_LIMITS: ParseLimits = ParseLimits {
    max_trace_bytes: 64 * 1024,
    max_record_bytes: 4 * 1024,
    max_records: 512,
};

fuzz_target!(|input: &[u8]| {
    let _ = parse_trace_bytes(input, FUZZ_LIMITS);
});
