//! Capability tokens. Execution requires an Authorization, which exists only if
//! a policy allowed the call, or a policy escalated it and a human approved.
//!
//! Fields are private to this module, so neither type can be forged
//! (tests/ui/forge_token.rs, tests/ui/forge_escalation.rs). A block is not an
//! Escalation, so no approval can ever turn a deny into an execution.

use authz_core::{Context, Decision, Policy, ToolCall};

use crate::approval::Approval;

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

/// A policy escalation awaiting a human. Only `authorize` creates one.
#[derive(Debug)]
pub struct Escalation {
    call: ToolCall,
    decision: Decision,
}

impl Escalation {
    pub fn call(&self) -> &ToolCall {
        &self.call
    }

    pub fn decision(&self) -> &Decision {
        &self.decision
    }
}

#[derive(Debug)]
pub enum Refusal {
    Blocked(Decision),
    Pending(Escalation),
}

pub fn authorize(p: &dyn Policy, call: &ToolCall, ctx: &Context) -> Result<Authorization, Refusal> {
    match p.decide(call, ctx) {
        Decision::Allow => Ok(Authorization { call: call.clone() }),
        d @ Decision::Escalate { .. } => {
            Err(Refusal::Pending(Escalation { call: call.clone(), decision: d }))
        }
        d => Err(Refusal::Blocked(d)),
    }
}

/// Consumes the escalation either way, so one approval authorizes exactly one call.
pub fn approve(e: Escalation, a: &Approval) -> Result<Authorization, Decision> {
    if a.granted { Ok(Authorization { call: e.call }) } else { Err(e.decision) }
}
