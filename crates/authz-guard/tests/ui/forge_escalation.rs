// Forging an Escalation (to then approve it) outside token.rs must not compile.
fn main() {
    let call = authz_core::ToolCall::new("shell_run", Default::default());
    let decision = authz_core::Decision::block("out-of-scope", "denied");
    let _ = authz_guard::token::Escalation { call, decision };
}
