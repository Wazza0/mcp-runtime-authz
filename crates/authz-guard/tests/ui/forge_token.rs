// Forging an Authorization outside token.rs must not compile.
fn main() {
    let call = authz_core::ToolCall::new("shell_run", Default::default());
    let _ = authz_guard::token::Authorization { call };
}
