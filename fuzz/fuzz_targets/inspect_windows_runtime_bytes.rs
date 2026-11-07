#![no_main]

use libfuzzer_sys::fuzz_target;
use sideeffect::windows_runtime::inspect_windows_runtime_bytes;

// Keep this cross-platform parser harness cheap. Production still enforces its
// larger document and JSON-value budgets; fuzz inputs here stay below 64 KiB.
fuzz_target!(|input: &[u8]| {
    let _ = inspect_windows_runtime_bytes(input);
});
