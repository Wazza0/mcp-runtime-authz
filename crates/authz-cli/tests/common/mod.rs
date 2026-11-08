use std::{path::Path, sync::Arc};

use authz_cli::{Brain, Rig};
use authz_guard::DenyAll;
use serde_json::Value;

pub fn rig() -> Rig {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    Rig {
        root: root.to_path_buf(),
        server: env!("CARGO_BIN_EXE_authz").into(),
        server_args: vec!["serve-tools".into()],
        brain: Brain::Scripted,
        approver: Arc::new(DenyAll),
    }
}

pub fn jsonl(p: &Path) -> Vec<Value> {
    authz_agent::scenario::read_events(p)
}
