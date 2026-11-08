//! The argument decoder sees attacker-shaped input on every call. It must never panic,
//! and decoding must never lose the original value.
#![no_main]

use authz_guard::inspect::{emails, hosts, query_len, shared, variants};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let (a, b) = s.split_at(s.char_indices().nth(s.chars().count() / 2).map_or(0, |(i, _)| i));
    let v = variants(&s);
    assert_eq!(v[0], s, "decoding dropped the original value");
    let _ = shared(a, b, 8);
    let _ = shared(&s, &s, 4);
    let _ = (emails(&s), hosts(&s), query_len(&s));
});
