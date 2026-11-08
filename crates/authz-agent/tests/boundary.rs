//! Structural boundary: agent logic cannot name the tool client or server.

#[test]
fn agent_crate_cannot_reach_tools() {
    let m = include_str!("../Cargo.toml");
    for forbidden in ["authz-guard", "authz-tools", "rmcp"] {
        assert!(!m.contains(forbidden), "authz-agent must not depend on {forbidden}");
    }
}
