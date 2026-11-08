//! The interceptor-only invariant is enforced by the compiler, not convention.

#[test]
fn bypasses_do_not_compile() {
    trybuild::TestCases::new().compile_fail("tests/ui/*.rs");
}
