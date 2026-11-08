// Calling the MCP client directly, skipping the interceptor, must not compile.
async fn bypass(m: &authz_guard::Mcp, c: &authz_core::ToolCall) {
    let _ = m.exec(c).await;
}

fn main() {}
