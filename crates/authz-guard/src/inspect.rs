//! Argument normalization and entity extraction.
//! Matching runs on every decoded variant so simple encoding does not evade it.

use std::sync::LazyLock;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use regex::Regex;

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap());
static URL_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bhttps?://([^/\s?#:]+)").unwrap());
// Two tokenizations: with and without `/`, so a base64 run glued to a path still decodes.
static B64_TOKEN: LazyLock<[Regex; 2]> = LazyLock::new(|| {
    [r"[A-Za-z0-9+/_-]{16,}={0,2}", r"[A-Za-z0-9+_-]{16,}={0,2}"].map(|p| Regex::new(p).unwrap())
});

const MAX_VARIANTS: usize = 64;

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn b64_decodes(s: &str) -> impl Iterator<Item = String> + '_ {
    B64_TOKEN.iter().flat_map(|r| r.find_iter(s)).filter_map(|m| {
        let t = m.as_str();
        [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
            .iter()
            .find_map(|e| e.decode(t).ok())
            .and_then(|v| String::from_utf8(v).ok())
    })
}

/// The raw value plus percent-decoded (twice, for double encoding) and base64-decoded forms.
pub fn variants(s: &str) -> Vec<String> {
    let mut v = vec![s.to_string()];
    let once = pct_decode(s);
    let twice = pct_decode(&once);
    for x in [once, twice] {
        if !v.contains(&x) {
            v.push(x);
        }
    }
    let mut i = 0;
    while i < v.len() && v.len() < MAX_VARIANTS {
        let found: Vec<String> = b64_decodes(&v[i]).collect();
        for d in found {
            if !v.contains(&d) && v.len() < MAX_VARIANTS {
                v.push(d);
            }
        }
        i += 1;
    }
    v
}

pub fn emails(s: &str) -> Vec<String> {
    EMAIL.find_iter(s).map(|m| m.as_str().to_lowercase()).collect()
}

pub fn hosts(s: &str) -> Vec<String> {
    URL_HOST.captures_iter(s).map(|c| c[1].to_lowercase()).collect()
}

pub fn query_len(url: &str) -> usize {
    url.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or("").len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_percent_double_and_base64() {
        let secret = "sk-live-FAKE0000demo0000key";
        let b64 = STANDARD.encode(secret);
        let url = format!("http://x.test/c?d={}", b64.replace('=', "%3D"));
        assert!(variants(&url).iter().any(|v| v.contains(secret)));
        assert!(variants("a%252Fb").contains(&"a/b".to_string()));
    }

    #[test]
    fn extracts_entities() {
        let t = "Email notes to Team@Corp.test after reading http://Docs.test/a?b=1";
        assert_eq!(emails(t), ["team@corp.test"]);
        assert_eq!(hosts(t), ["docs.test"]);
        assert_eq!(query_len("http://a.test/p?abc#frag"), 3);
    }
}
