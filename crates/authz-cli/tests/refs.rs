//! Every corpus framework ref resolves against eval/frameworks/; attacks carry ASI and ATLAS refs.

mod common;

use std::fs;

use authz_agent::Kind;
use authz_cli::load;
use serde_json::Value;

#[test]
fn corpus_refs_resolve() {
    let r = common::rig();
    let fw = |name: &str| -> Value {
        let p = r.root.join("eval").join("frameworks").join(name);
        serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap()
    };
    let (owasp, atlas) = (fw("owasp.json"), fw("atlas.json"));
    let cases = load(&r.corpus()).unwrap();
    assert!(!cases.is_empty(), "empty corpus");
    let mut bad = vec![];
    for s in &cases {
        for (list, ids, known) in [
            ("asi", &s.refs.asi, &owasp["asi"]),
            ("llm", &s.refs.llm, &owasp["llm"]),
            ("atlas", &s.refs.atlas, &atlas["techniques"]),
        ] {
            assert!(known.is_object(), "no {list} table in eval/frameworks");
            for id in ids.iter().filter(|id| known.get(id.as_str()).is_none()) {
                bad.push(format!("{}: unknown {list} id {id}", s.id));
            }
        }
        if s.kind == Kind::Attack {
            if s.refs.asi.is_empty() {
                bad.push(format!("{}: attack has no asi ref", s.id));
            }
            if s.refs.atlas.is_empty() {
                bad.push(format!("{}: attack has no atlas ref", s.id));
            }
        }
    }
    assert!(bad.is_empty(), "bad corpus refs:\n{}", bad.join("\n"));
}
