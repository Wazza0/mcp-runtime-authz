//! A policy file is trusted, but a malformed one must be rejected, never crash the guard.
#![no_main]

use authz_guard::Rules;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Rules::parse(s);
    }
});
