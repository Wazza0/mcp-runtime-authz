//! Capability token. Execution requires one; only a policy Allow mints one.
//!
//! The field is private to this module, so nothing else can forge one.
//! Proven by tests/ui/forge_token.rs (trybuild).

use authz_core::{Context, Decision, Policy, ToolCall};

/// Proof that `call` was allowed. Bound to that exact call, consumed on use, not Clone.
#[derive(Debug)]
pub struct Authorization {
    call: ToolCall,
}

impl Authorization {
    pub fn call(&self) -> &ToolCall {
        &self.call
    }
}

/// The only constructor. Escalate and Block both come back as Err.
pub fn authorize(
    p: &dyn Policy,
    call: &ToolCall,
    ctx: &Context,
) -> Result<Authorization, Decision> {
    match p.decide(call, ctx) {
        Decision::Allow => Ok(Authorization { call: call.clone() }),
        d => Err(d),
    }
}
