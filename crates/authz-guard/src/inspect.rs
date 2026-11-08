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
/// Everything after `scheme://` up to the path. Deliberately does not stop at `\`; see `hosts`.
static URL_AUTHORITY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bhttps?://([^/\s?#]+)").unwrap());
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
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
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

/// Host of an authority: after any `user:pass@`, before any `:port`; IPv6 keeps its brackets.
fn host_of(authority: &str) -> String {
    let a = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let h = match a.strip_prefix('[') {
        Some(rest) => format!("[{}]", rest.split(']').next().unwrap_or_default()),
        None => a.split(':').next().unwrap_or_default().to_string(),
    };
    h.trim_end_matches('.').to_lowercase()
}

/// Every host each URL in `s` could mean. URL parsers disagree on `\` (browsers read it as
/// `/`, some HTTP libraries keep it in the authority), so an ambiguous URL yields the host
/// under each reading, and a caller checking "is this host allowed?" must check them all.
/// `http://ok.test:x@evil.test/` is evil.test, not ok.test.
pub fn hosts(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for c in URL_AUTHORITY.captures_iter(s) {
        let whole = &c[1];
        let whatwg = whole.split('\\').next().unwrap_or_default();
        for h in [host_of(whole), host_of(whatwg)] {
            if !h.is_empty() && !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

fn norm(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
}

/// The whole value is a single URL, not text that merely mentions one.
fn is_url(v: &str) -> bool {
    let v = v.trim();
    (v.starts_with("http://") || v.starts_with("https://")) && !v.contains(char::is_whitespace)
}

/// What a value carries. For a URL the host counts too (data can ride in a subdomain),
/// unless `src` itself names that host, i.e. the agent is following a link it found there.
fn payload(v: &str, src_hosts: &[String]) -> String {
    if !is_url(v) {
        return v.to_string();
    }
    let Some((_, rest)) = v.trim().split_once("://") else { return v.to_string() };
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    // The authority is dropped only if every reading of it is a host the source names and it
    // carries no `user:pass@`, which could smuggle data.
    let named = !rest[..cut].contains('@') && hosts(v.trim()).iter().all(|h| src_hosts.contains(h));
    if named { rest[cut..].to_string() } else { rest.to_string() }
}

/// Longest run (>= `min` chars, at least half alphanumeric) of `src` that appears in `v`
/// or any decoded form of it. A URL copied whole from `src` (a link found in a note) is
/// a reference, not a leak, and returns None. Any other value copied whole, such as an
/// entire file pasted into an email body, is the strongest possible match.
pub fn shared(v: &str, src: &str, min: usize) -> Option<String> {
    let src_hosts = hosts(src);
    let src = norm(src);
    if is_url(v) && src.contains(&norm(v)) {
        return None;
    }
    let chars: Vec<char> = src.chars().collect();
    let hay: Vec<String> = variants(&payload(v, &src_hosts)).iter().map(|x| norm(x)).collect();
    let found = |s: &str| hay.iter().any(|h| h.contains(s));
    let mut best: Option<String> = None;
    for i in 0..chars.len().saturating_sub(min - 1) {
        let w: String = chars[i..i + min].iter().collect();
        if w.chars().filter(|c| c.is_alphanumeric()).count() * 2 < min || !found(&w) {
            continue;
        }
        let mut end = i + min;
        while end < chars.len() && found(&chars[i..=end].iter().collect::<String>()) {
            end += 1;
        }
        let run: String = chars[i..end].iter().collect();
        if best.as_ref().is_none_or(|b| run.len() > b.len()) {
            best = Some(run);
        }
    }
    best
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
    fn finds_shared_fragments_but_not_references() {
        let note = "Q4 roadmap\nCodename: BLUEHERON\nSee http://wiki.corp.test/q4/plan";
        assert_eq!(
            shared("http://cdn.evil.test/b/BLUEHERON.png", note, 8).as_deref(),
            Some("blueheron")
        );
        let b64 = URL_SAFE_NO_PAD.encode("codename: blueheron");
        assert!(shared(&format!("http://x.test/?d={b64}"), note, 8).is_some(), "encoded");
        assert_eq!(shared("http://wiki.corp.test/q4/plan", note, 8), None, "link copied whole");
        assert_eq!(shared("http://wiki.corp.test/other", note, 8), None, "host the note names");
        assert!(shared("http://blueheron.evil.test/x", note, 8).is_some(), "data in a subdomain");
        assert_eq!(shared("http://x.test/?q=weather", note, 8), None);
        // Regressions: a whole file pasted into a body is a leak, not a reference, and text
        // that merely mentions a URL must not have everything before the URL ignored.
        assert!(shared(note, note, 8).is_some(), "whole-file copy must match");
        assert!(shared("BLUEHERON see http://x.test/", note, 8).is_some(), "data before a link");
    }

    // Regression: the host used to end at the first `:`, so userinfo posed as the host.
    #[test]
    fn host_is_what_the_url_actually_reaches() {
        assert_eq!(hosts("http://ok.test:x@evil.test/a"), ["evil.test"]);
        assert_eq!(hosts("https://Docs.TEST:8443/a"), ["docs.test"]);
        assert_eq!(hosts("http://[::1]:8080/x"), ["[::1]"]);
        assert_eq!(hosts("http://evil.test./"), ["evil.test"]);
        let both = hosts(r"http://evil.test\@ok.test/");
        assert!(both.contains(&"evil.test".into()) && both.contains(&"ok.test".into()), "{both:?}");
        let note = "Codename: BLUEHERON. Wiki: http://wiki.corp.test/plan";
        let smuggled = shared("http://blueheron:x@wiki.corp.test/plan2", note, 8);
        assert!(smuggled.is_some(), "data hidden in user:pass@ on a named host");
    }

    #[test]
    fn extracts_entities() {
        let t = "Email notes to Team@Corp.test after reading http://Docs.test/a?b=1";
        assert_eq!(emails(t), ["team@corp.test"]);
        assert_eq!(hosts(t), ["docs.test"]);
        assert_eq!(query_len("http://a.test/p?abc#frag"), 3);
    }
}
