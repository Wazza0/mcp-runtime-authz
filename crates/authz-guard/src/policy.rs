//! Declarative policy loaded from YAML. The engine stays generic; rules are data.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context as _, Result};
use authz_core::{Context, Decision, Policy, ToolCall};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Escalate,
}

/// M1: static per-tool allowlist. Unlisted tools fall to `default`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    pub default: Action,
    #[serde(default)]
    pub tools: BTreeMap<String, Action>,
}

impl Rules {
    pub fn load(p: &Path) -> Result<Self> {
        let s = fs::read_to_string(p).with_context(|| p.display().to_string())?;
        Self::parse(&s).with_context(|| p.display().to_string())
    }

    pub fn parse(s: &str) -> Result<Self> {
        Ok(serde_saphyr::from_str(s)?)
    }

    /// Explicit no-restriction baseline. Same code path, every call still audited.
    pub fn permit_all() -> Self {
        Self { default: Action::Allow, tools: BTreeMap::new() }
    }
}

impl Policy for Rules {
    fn decide(&self, call: &ToolCall, _ctx: &Context) -> Decision {
        let (a, rule) = match self.tools.get(&call.tool) {
            Some(a) => (*a, format!("tools.{}", call.tool)),
            None => (self.default, "default".into()),
        };
        match a {
            Action::Allow => Decision::Allow,
            Action::Deny => Decision::block(&rule, format!("{} is not permitted", call.tool)),
            Action::Escalate => {
                Decision::escalate(&rule, format!("{} requires approval", call.tool))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(t: &str) -> ToolCall {
        ToolCall::new(t, Default::default())
    }

    #[test]
    fn unlisted_tool_falls_to_default_deny() {
        let r = Rules::parse("default: deny\ntools: {fs_read: allow}").unwrap();
        let d = r.decide(&call("rm_rf"), &Context::default());
        assert_eq!(d.rule(), "default");
        assert!(!d.allowed());
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let y = "default: deny\ntools:\n  shell_run: deny\n  shell_run: allow\n";
        assert!(Rules::parse(y).is_err(), "a later duplicate must not silently re-allow");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(Rules::parse("default: deny\ntoolz: {shell_run: allow}").is_err());
    }

    #[test]
    fn escalate_is_not_an_allow() {
        let r = Rules::parse("default: escalate").unwrap();
        assert!(matches!(r.decide(&call("email_send"), &Context::default()), Decision::Escalate { .. }));
    }
}
