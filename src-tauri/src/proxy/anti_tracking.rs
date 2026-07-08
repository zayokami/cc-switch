//! Anti-tracking sanitizer for outbound Claude (Anthropic-format) requests.
//!
//! Background: Claude Code versions 2.1.91–2.1.196 shipped an obfuscated
//! mechanism that, when it detected a China timezone / proxy, covertly marked
//! each request by steganographically altering the injected system prompt —
//! swapping the apostrophe in "Today's date is …" for a visually identical
//! homoglyph and flipping the date separator (`2026-06-30` → `2026/06/30`), plus
//! zero-width characters. Those tiny, machine-parseable variations let the
//! server fingerprint the user's locale/environment without any visible cue.
//! (Anthropic acknowledged the mechanism and rolled it back in July 2026.)
//!
//! CC Switch already proxies Claude traffic, so it can strip these markers from
//! the request body before forwarding upstream. This module does exactly that —
//! **surgically**: it only touches the specific injected date line and removes
//! unambiguously illegitimate invisible characters, so legitimate prompt text
//! (including intentional curly quotes elsewhere) is never rewritten.
//!
//! Limitation: this can only sanitize traffic that actually flows through the
//! CC Switch proxy. Requests sent by a Claude Code client straight to Anthropic
//! never reach here.

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-lifetime count of tracking markers the proxy has stripped, surfaced
/// to the UI so users can see the protection is doing something. Counts every
/// normalized marker line plus every invisible char removed.
static MARKERS_STRIPPED: AtomicU64 = AtomicU64::new(0);

/// Total tracking markers stripped since the app started.
pub fn markers_stripped_total() -> u64 {
    MARKERS_STRIPPED.load(Ordering::Relaxed)
}

/// Invisible / zero-width code points that never legitimately appear in a
/// system prompt and are a classic covert-signaling channel. Stripped globally.
const INVISIBLE_CHARS: &[char] = &[
    '\u{200B}', // ZERO WIDTH SPACE
    '\u{200C}', // ZERO WIDTH NON-JOINER
    '\u{200D}', // ZERO WIDTH JOINER
    '\u{2060}', // WORD JOINER
    '\u{FEFF}', // ZERO WIDTH NO-BREAK SPACE / BOM
    '\u{180E}', // MONGOLIAN VOWEL SEPARATOR
    '\u{00AD}', // SOFT HYPHEN
];

/// Apostrophe homoglyphs the marker may swap in for the ASCII `'` in "Today's".
const APOSTROPHE_HOMOGLYPHS: &[char] = &[
    '\u{2018}', // LEFT SINGLE QUOTATION MARK
    '\u{2019}', // RIGHT SINGLE QUOTATION MARK
    '\u{02BC}', // MODIFIER LETTER APOSTROPHE
    '\u{00B4}', // ACUTE ACCENT
    '\u{0060}', // GRAVE ACCENT
    '\u{FF07}', // FULLWIDTH APOSTROPHE
];

/// Matches the injected "Today['?]s date is <date>" line, tolerating any
/// apostrophe variant (or none) and either date separator. Case-insensitive on
/// the literal words; captures the apostrophe char and the three date fields so
/// they can be normalized in place without disturbing the rest of the line.
static DATE_LINE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(today)([\x{2018}\x{2019}\x{02BC}\x{00B4}\x{0060}\x{FF07}']?)(s date is\s+)(\d{4})([/-])(\d{2})([/-])(\d{2})",
    )
    .expect("anti-tracking date-line regex is valid")
});

/// What the sanitizer changed on a single request.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AntiTrackingReport {
    /// Number of invisible/zero-width code points removed.
    pub invisible_removed: usize,
    /// Number of "Today's date is …" marker lines normalized (apostrophe and/or
    /// separator restored to their canonical ASCII form).
    pub date_markers_normalized: usize,
}

impl AntiTrackingReport {
    pub fn changed(&self) -> bool {
        self.invisible_removed > 0 || self.date_markers_normalized > 0
    }

    fn merge(&mut self, other: &AntiTrackingReport) {
        self.invisible_removed += other.invisible_removed;
        self.date_markers_normalized += other.date_markers_normalized;
    }
}

/// Sanitize the system prompt of an Anthropic-format request body in place,
/// stripping known Claude Code tracking markers. Returns a report of what was
/// changed; the body is only mutated when something was actually found.
///
/// The Anthropic `system` field is either a plain string or an array of content
/// blocks (`[{ "type": "text", "text": "…" }, …]`); both shapes are handled.
pub fn sanitize_claude_tracking_markers(body: &mut Value) -> AntiTrackingReport {
    let mut report = AntiTrackingReport::default();

    let Some(system) = body.get_mut("system") else {
        return report;
    };

    match system {
        Value::String(text) => {
            if let Some(clean) = sanitize_text(text, &mut report) {
                *text = clean;
            }
        }
        Value::Array(blocks) => {
            for block in blocks.iter_mut() {
                if let Some(text_val) = block.get_mut("text").and_then(|t| {
                    if t.is_string() {
                        Some(t)
                    } else {
                        None
                    }
                }) {
                    let current = text_val.as_str().unwrap_or_default();
                    if let Some(clean) = sanitize_text(current, &mut report) {
                        *text_val = Value::String(clean);
                    }
                }
            }
        }
        _ => {}
    }

    report
}

/// Forwarder entry point: when the anti-tracking toggle is on and the request is
/// Anthropic-format (Claude), strip tracking markers from `body` in place and
/// bump the process counter. No-op for other app types or when disabled.
///
/// Returns the report so the caller can log; the body is only mutated on a hit.
pub fn apply_if_enabled(app_type: &crate::app_config::AppType, body: &mut Value) -> AntiTrackingReport {
    // Only Claude (Anthropic wire format) carries the injected "Today's date
    // is …" system prompt this targets. Claude Desktop is not proxied here.
    if !matches!(app_type, crate::app_config::AppType::Claude) {
        return AntiTrackingReport::default();
    }
    if !crate::settings::claude_anti_tracking_enabled() {
        return AntiTrackingReport::default();
    }

    let report = sanitize_claude_tracking_markers(body);
    if report.changed() {
        let total = report.invisible_removed + report.date_markers_normalized;
        MARKERS_STRIPPED.fetch_add(total as u64, Ordering::Relaxed);
        log::info!(
            "[anti-tracking] stripped Claude tracking markers: {} date marker(s), {} invisible char(s)",
            report.date_markers_normalized,
            report.invisible_removed
        );
    }
    report
}
/// made (so callers can avoid touching the JSON when nothing matched), and
/// records what changed in `report`.
fn sanitize_text(input: &str, report: &mut AntiTrackingReport) -> Option<String> {
    let mut local = AntiTrackingReport::default();

    // 1) Strip invisible / zero-width code points (global, unambiguous).
    let (stripped, removed) = strip_invisible(input);
    local.invisible_removed = removed;

    // 2) Normalize the injected "Today's date is <date>" marker line only.
    //    The regex also matches the already-canonical form, so we compare each
    //    match against its normalized rewrite and only count/emit a change when
    //    it actually differs — a clean prompt must pass through untouched.
    let normalized = DATE_LINE_RE.replace_all(&stripped, |caps: &regex::Captures| {
        let original = &caps[0];
        let canonical = format!(
            "{}'{}{}-{}-{}",
            &caps[1], // "Today" (original case preserved)
            &caps[3], // "s date is " + whitespace
            &caps[4], // YYYY
            &caps[6], // MM
            &caps[8], // DD
        );
        if canonical != *original {
            local.date_markers_normalized += 1;
        }
        canonical
    });

    report.merge(&local);

    if local.changed() {
        Some(normalized.into_owned())
    } else {
        None
    }
}

/// Remove all invisible/zero-width code points, returning the cleaned string and
/// how many were removed.
fn strip_invisible(input: &str) -> (String, usize) {
    if !input.chars().any(|c| INVISIBLE_CHARS.contains(&c)) {
        return (input.to_string(), 0);
    }
    let mut removed = 0;
    let cleaned: String = input
        .chars()
        .filter(|c| {
            if INVISIBLE_CHARS.contains(c) {
                removed += 1;
                false
            } else {
                true
            }
        })
        .collect();
    (cleaned, removed)
}

/// Exposed for reuse/testing: is this char an apostrophe homoglyph the marker
/// could use? (The regex already covers detection; this documents the set.)
#[allow(dead_code)]
pub fn is_apostrophe_homoglyph(c: char) -> bool {
    APOSTROPHE_HOMOGLYPHS.contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalizes_slash_date_and_homoglyph_apostrophe_in_string_system() {
        // Marker form: right-single-quote apostrophe + slash separators.
        let mut body = json!({
            "system": "You are Claude.\nToday\u{2019}s date is 2026/06/30.\nBe helpful.",
            "messages": []
        });
        let report = sanitize_claude_tracking_markers(&mut body);
        assert_eq!(report.date_markers_normalized, 1);
        assert!(report.changed());
        assert_eq!(
            body["system"].as_str().unwrap(),
            "You are Claude.\nToday's date is 2026-06-30.\nBe helpful."
        );
    }

    #[test]
    fn normalizes_marker_inside_content_block_array() {
        let mut body = json!({
            "system": [
                { "type": "text", "text": "System preamble." },
                { "type": "text", "text": "Today\u{02BC}s date is 2026/01/02" }
            ]
        });
        let report = sanitize_claude_tracking_markers(&mut body);
        assert_eq!(report.date_markers_normalized, 1);
        assert_eq!(
            body["system"][1]["text"].as_str().unwrap(),
            "Today's date is 2026-01-02"
        );
        // Untouched block stays byte-identical.
        assert_eq!(body["system"][0]["text"].as_str().unwrap(), "System preamble.");
    }

    #[test]
    fn strips_zero_width_characters() {
        let mut body = json!({
            "system": "Hello\u{200B}\u{200D}world\u{FEFF}."
        });
        let report = sanitize_claude_tracking_markers(&mut body);
        assert_eq!(report.invisible_removed, 3);
        assert_eq!(body["system"].as_str().unwrap(), "Helloworld.");
    }

    #[test]
    fn clean_prompt_is_left_untouched() {
        let original = json!({
            "system": "You are Claude.\nToday's date is 2026-06-30.\nUser's request follows.",
            "messages": [{ "role": "user", "content": "hi" }]
        });
        let mut body = original.clone();
        let report = sanitize_claude_tracking_markers(&mut body);
        assert!(!report.changed(), "already-clean prompt must not be altered");
        assert_eq!(body, original);
    }

    #[test]
    fn does_not_touch_legitimate_curly_quotes_outside_marker_line() {
        // A curly apostrophe in ordinary prose must survive — only the date
        // marker line is normalized.
        let mut body = json!({
            "system": "The user\u{2019}s preferences matter.\nToday's date is 2026-06-30."
        });
        let report = sanitize_claude_tracking_markers(&mut body);
        assert!(!report.changed());
        assert_eq!(
            body["system"].as_str().unwrap(),
            "The user\u{2019}s preferences matter.\nToday's date is 2026-06-30."
        );
    }

    #[test]
    fn handles_missing_system_field() {
        let mut body = json!({ "messages": [] });
        let report = sanitize_claude_tracking_markers(&mut body);
        assert!(!report.changed());
    }

    #[test]
    fn normalizes_only_separator_when_apostrophe_already_ascii() {
        let mut body = json!({ "system": "Today's date is 2026/12/31" });
        let report = sanitize_claude_tracking_markers(&mut body);
        assert_eq!(report.date_markers_normalized, 1);
        assert_eq!(body["system"].as_str().unwrap(), "Today's date is 2026-12-31");
    }
}
