//! Parser for the Prometheus text exposition format (version 0.0.4) with
//! pragmatic `OpenMetrics` tolerance.
//!
//! The parser is single-pass and operates directly on the input bytes. It
//! allocates only the output `String`s (metric names, label names, label
//! values). Label values without backslash escapes take a zero-copy-ish fast
//! path (slice + `to_owned`); only values containing a `\` are unescaped
//! character by character.
//!
//! Reference: <https://prometheus.io/docs/instrumenting/exposition_formats/>

use crate::model::{
    Label,
    METRIC_NAME_LABEL,
    Sample,
    TimeSeries,
};

/// Error produced when a scrape body cannot be parsed.
///
/// Carries the 1-based line number of the offending line and a human-readable
/// message. The whole scrape fails on any malformed line, matching Prometheus
/// behaviour.
#[derive(Debug, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct ParseError {
    line: usize,
    message: String,
}

impl ParseError {
    fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }

    /// The 1-based line number the error occurred on.
    #[must_use]
    pub fn line(&self) -> usize {
        self.line
    }

    /// The human-readable error message (without the line prefix).
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Parse a scrape body into remote-write-ready series, one [`TimeSeries`] per
/// sample line (each holding a single sample).
///
/// `default_timestamp_ms` is the scrape start time; it is used when a line has
/// no explicit timestamp, or for every sample when `honor_timestamps` is
/// `false`.
///
/// Labels in the output are ordered with `__name__` first, then the remaining
/// labels in order of appearance. They are intentionally left unsorted; the
/// scrape pipeline sorts later, after adding job/instance labels.
pub fn parse(
    body: &str,
    default_timestamp_ms: i64,
    honor_timestamps: bool,
) -> Result<Vec<TimeSeries>, ParseError> {
    let bytes = body.as_bytes();
    // Heuristic pre-size: most non-comment, non-blank lines yield one series.
    // Counting newlines over-estimates (comments/blanks) but avoids repeated
    // re-allocation on large bodies.
    let estimate = memchr::memchr_iter(b'\n', bytes).count().saturating_add(1);
    let mut out = Vec::with_capacity(estimate.min(1 << 16));

    let mut line_no: usize = 0;
    let mut pos: usize = 0;
    let len = bytes.len();

    while pos < len {
        line_no += 1;
        // Find end of the current line.
        let line_start = pos;
        let line_end = memchr::memchr(b'\n', &bytes[pos..]).map_or(len, |offset| pos + offset);
        // Next iteration starts after the '\n' (or at len if none).
        pos = if line_end < len {
            line_end + 1
        } else {
            line_end
        };

        // Strip a trailing '\r'.
        let mut end = line_end;
        if end > line_start && bytes[end - 1] == b'\r' {
            end -= 1;
        }

        if let Some(series) = parse_line(
            body,
            line_start,
            end,
            line_no,
            default_timestamp_ms,
            honor_timestamps,
        )? {
            out.push(series);
        }
    }

    Ok(out)
}

/// Return `true` for ASCII space or tab.
fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// Per-byte class bits for name scanning, indexed by byte value. One table
/// lookup replaces the alphanumeric/underscore/colon comparison chain in the
/// hottest parser loops.
const NAME_START: u8 = 1 << 0; // [a-zA-Z_]
const NAME_CONTINUE: u8 = 1 << 1; // [a-zA-Z0-9_]
const NAME_COLON: u8 = 1 << 2; // ':'

const NAME_CLASS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut b = 0usize;
    while b < 256 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "loop index is a byte value"
        )]
        let byte = b as u8;
        if byte.is_ascii_alphabetic() || byte == b'_' {
            table[b] = NAME_START | NAME_CONTINUE;
        } else if byte.is_ascii_digit() {
            table[b] = NAME_CONTINUE;
        } else if byte == b':' {
            table[b] = NAME_COLON;
        }
        b += 1;
    }
    table
};

/// First byte of a metric name / label name: `[a-zA-Z_:]` (label names
/// disallow `:`, checked by the caller passing `allow_colon`).
fn is_name_start(b: u8, allow_colon: bool) -> bool {
    let class = NAME_CLASS[b as usize];
    class & NAME_START != 0 || (allow_colon && class & NAME_COLON != 0)
}

/// Continuation byte of a name: `[a-zA-Z0-9_:]` (`:` gated by `allow_colon`).
fn is_name_continue(b: u8, allow_colon: bool) -> bool {
    let class = NAME_CLASS[b as usize];
    class & NAME_CONTINUE != 0 || (allow_colon && class & NAME_COLON != 0)
}

/// Parse a single (already delimited) line.
///
/// `start..end` is the line content excluding the newline and trailing `\r`.
/// Returns `Ok(None)` for blank and comment lines.
fn parse_line(
    body: &str,
    start: usize,
    end: usize,
    line_no: usize,
    default_timestamp_ms: i64,
    honor_timestamps: bool,
) -> Result<Option<TimeSeries>, ParseError> {
    let bytes = body.as_bytes();
    let mut i = start;

    // Skip leading whitespace.
    while i < end && is_space(bytes[i]) {
        i += 1;
    }

    // Blank line.
    if i >= end {
        return Ok(None);
    }

    // Comment line (# HELP, # TYPE, # EOF, ...).
    if bytes[i] == b'#' {
        return Ok(None);
    }

    // --- metric name ---
    if !is_name_start(bytes[i], true) {
        return Err(ParseError::new(
            line_no,
            format!("invalid start of metric name: {:?}", bytes[i] as char),
        ));
    }
    let name_start = i;
    i += 1;
    while i < end && is_name_continue(bytes[i], true) {
        i += 1;
    }
    // Metric name is ASCII by construction, so this slice is valid UTF-8.
    let metric_name = str_from(body, name_start, i);

    // Reserve label slots: name + however many appear.
    // Headroom beyond typical exposition label counts: the scrape pipeline
    // appends job/instance/external labels and relabeling may add more —
    // sizing for that here avoids one realloc per series downstream.
    let mut labels: Vec<Label> = Vec::with_capacity(12);
    labels.push(Label::new(METRIC_NAME_LABEL, metric_name));

    // Optional whitespace between name and '{' or value. Prometheus is strict
    // here, but we are lenient.
    while i < end && is_space(bytes[i]) {
        i += 1;
    }

    // --- optional label set ---
    if i < end && bytes[i] == b'{' {
        i = parse_labels(body, i, end, line_no, &mut labels)?;
        // Optional whitespace before value.
        while i < end && is_space(bytes[i]) {
            i += 1;
        }
    }

    // --- value ---
    if i >= end {
        return Err(ParseError::new(line_no, "missing value"));
    }
    let value_start = i;
    while i < end && !is_space(bytes[i]) {
        i += 1;
    }
    let value_tok = str_from(body, value_start, i);
    let value = parse_value(value_tok)
        .ok_or_else(|| ParseError::new(line_no, format!("invalid value: {value_tok:?}")))?;

    // Skip whitespace after value.
    while i < end && is_space(bytes[i]) {
        i += 1;
    }

    // --- optional timestamp / exemplar ---
    let mut timestamp = default_timestamp_ms;
    if i < end && bytes[i] != b'#' {
        // Timestamp token.
        let ts_start = i;
        while i < end && !is_space(bytes[i]) {
            i += 1;
        }
        let ts_tok = str_from(body, ts_start, i);
        let parsed = parse_timestamp(ts_tok)
            .ok_or_else(|| ParseError::new(line_no, format!("invalid timestamp: {ts_tok:?}")))?;
        if honor_timestamps {
            timestamp = parsed;
        }

        // Skip whitespace after timestamp.
        while i < end && is_space(bytes[i]) {
            i += 1;
        }
    }

    // After value (and optional timestamp) only an exemplar (starting with '#')
    // is allowed; anything else is garbage.
    if i < end {
        if bytes[i] == b'#' {
            // OpenMetrics exemplar suffix: ignore the remainder of the line.
        } else {
            return Err(ParseError::new(
                line_no,
                format!("unexpected trailing content: {:?}", str_from(body, i, end)),
            ));
        }
    }

    if !honor_timestamps {
        timestamp = default_timestamp_ms;
    }

    Ok(Some(TimeSeries {
        labels,
        sample: Sample { value, timestamp },
        labels_hash: 0,
    }))
}

/// Parse the label set starting at `bytes[open]` (which must be `{`). Returns
/// the index just past the closing `}`.
fn parse_labels(
    body: &str,
    open: usize,
    end: usize,
    line_no: usize,
    labels: &mut Vec<Label>,
) -> Result<usize, ParseError> {
    let bytes = body.as_bytes();
    debug_assert_eq!(bytes[open], b'{');
    let mut i = open + 1;

    loop {
        // Skip whitespace.
        while i < end && is_space(bytes[i]) {
            i += 1;
        }
        if i >= end {
            return Err(ParseError::new(
                line_no,
                "unterminated label set (expected '}')",
            ));
        }
        // Closing brace (possibly after a trailing comma or empty set).
        if bytes[i] == b'}' {
            return Ok(i + 1);
        }

        // --- label name ---
        if !is_name_start(bytes[i], false) {
            return Err(ParseError::new(
                line_no,
                format!("invalid start of label name: {:?}", bytes[i] as char),
            ));
        }
        let name_start = i;
        i += 1;
        while i < end && is_name_continue(bytes[i], false) {
            i += 1;
        }
        let name = str_from(body, name_start, i);

        if name == METRIC_NAME_LABEL {
            return Err(ParseError::new(
                line_no,
                "label name '__name__' is not allowed inside braces",
            ));
        }
        if labels.iter().any(|l| l.name == name) {
            return Err(ParseError::new(
                line_no,
                format!("duplicate label name: {name:?}"),
            ));
        }

        // Optional whitespace, then '='.
        while i < end && is_space(bytes[i]) {
            i += 1;
        }
        if i >= end || bytes[i] != b'=' {
            return Err(ParseError::new(
                line_no,
                format!("expected '=' after label name {name:?}"),
            ));
        }
        i += 1;
        // Optional whitespace, then opening quote.
        while i < end && is_space(bytes[i]) {
            i += 1;
        }
        if i >= end || bytes[i] != b'"' {
            return Err(ParseError::new(
                line_no,
                format!("expected '\"' to start value of label {name:?}"),
            ));
        }

        // --- label value (double-quoted) ---
        let (value, next) = parse_label_value(body, i, end, line_no)?;
        i = next;

        labels.push(Label::new(name, value));

        // Skip whitespace after value.
        while i < end && is_space(bytes[i]) {
            i += 1;
        }
        if i >= end {
            return Err(ParseError::new(
                line_no,
                "unterminated label set (expected '}')",
            ));
        }
        match bytes[i] {
            b',' => {
                i += 1;
                // Loop; a following '}' (trailing comma) is handled at the top.
            }
            b'}' => return Ok(i + 1),
            other => {
                return Err(ParseError::new(
                    line_no,
                    format!(
                        "expected ',' or '}}' after label value, found {:?}",
                        other as char
                    ),
                ));
            }
        }
    }
}

/// Parse a double-quoted label value starting at `bytes[open]` (the opening
/// `"`). Returns the decoded value and the index just past the closing quote.
///
/// Fast path: when the value contains no backslash, the raw slice is validated
/// as UTF-8 and copied once. Slow path (backslash present) decodes escapes
/// char by char.
fn parse_label_value(
    body: &str,
    open: usize,
    end: usize,
    line_no: usize,
) -> Result<(compact_str::CompactString, usize), ParseError> {
    let bytes = body.as_bytes();
    debug_assert_eq!(bytes[open], b'"');
    let content_start = open + 1;
    let mut i = content_start;
    let mut has_escape = false;

    // Scan for the closing quote, noting whether any escape is present.
    loop {
        let Some(offset) = memchr::memchr2(b'"', b'\\', &bytes[i..end]) else {
            return Err(ParseError::new(
                line_no,
                "unterminated label value (missing closing '\"')",
            ));
        };
        i += offset;
        if bytes[i] == b'"' {
            break;
        }
        has_escape = true;
        // Skip the backslash and the escaped byte so an escaped
        // quote/backslash does not terminate the scan. Validation happens in
        // the slow path.
        if i + 1 >= end {
            return Err(ParseError::new(
                line_no,
                "unterminated label value (trailing backslash)",
            ));
        }
        i += 2;
    }
    let close = i;

    if !has_escape {
        let s = utf8_from(body, content_start, close, line_no)?;
        // Values up to 24 bytes are stored inline — no allocation.
        return Ok((compact_str::CompactString::from(s), close + 1));
    }

    // Slow path: decode escapes.
    let raw = &bytes[content_start..close];
    let mut decoded = String::with_capacity(raw.len());
    let mut j = 0;
    while j < raw.len() {
        let b = raw[j];
        if b == b'\\' {
            j += 1;
            // Guaranteed present by the scan above.
            match raw[j] {
                b'\\' => decoded.push('\\'),
                b'"' => decoded.push('"'),
                b'n' => decoded.push('\n'),
                other => {
                    return Err(ParseError::new(
                        line_no,
                        format!("invalid escape sequence: \\{}", other as char),
                    ));
                }
            }
            j += 1;
        } else {
            // Copy a maximal run of non-backslash bytes, then validate the
            // whole decoded string as UTF-8 at the end via from_utf8 below.
            let run_start = j;
            while j < raw.len() && raw[j] != b'\\' {
                j += 1;
            }
            // The run is a slice of the original body; validate it as UTF-8.
            let run = utf8_from(body, content_start + run_start, content_start + j, line_no)?;
            decoded.push_str(run);
        }
    }

    Ok((decoded.into(), close + 1))
}

/// Parse a metric value. Handles a leading `+` (e.g. `+Inf`); otherwise defers
/// to `f64::from_str`, which accepts `inf`/`infinity`/`nan` case-insensitively.
fn parse_value(tok: &str) -> Option<f64> {
    if tok.is_empty() {
        return None;
    }
    // `f64::from_str` rejects a leading '+' on infinities in some Rust versions;
    // strip it for the special forms. It DOES accept "+1.0" etc., so only strip
    // when the remainder is non-numeric-looking is unnecessary — from_str
    // handles "+..." for finite numbers. Try direct parse first.
    if let Ok(v) = tok.parse::<f64>() {
        return Some(v);
    }
    // Fallback: strip a single leading '+' and retry (covers "+Inf").
    if let Some(rest) = tok.strip_prefix('+')
        && let Ok(v) = rest.parse::<f64>()
    {
        return Some(v);
    }
    None
}

/// Parse a timestamp token into milliseconds since the epoch.
///
/// Pragmatic `OpenMetrics` extension: a token containing `.`, `e`, or `E` is
/// treated as floating-point seconds and converted to milliseconds (rounded).
/// Otherwise it is parsed as an integer number of milliseconds.
fn parse_timestamp(tok: &str) -> Option<i64> {
    if tok.is_empty() {
        return None;
    }
    if tok.bytes().any(|b| b == b'.' || b == b'e' || b == b'E') {
        let secs = tok.parse::<f64>().ok()?;
        if !secs.is_finite() {
            return None;
        }
        let ms = (secs * 1000.0).round();
        // Guard against out-of-range conversions. The i64::MIN/MAX bounds lose
        // precision when cast to f64, which only widens the accepted range by a
        // few ULPs; the subsequent `as i64` saturates, so this is safe.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            reason = "range is checked before the cast; bound precision loss is harmless"
        )]
        if ms >= i64::MIN as f64 && ms <= i64::MAX as f64 {
            Some(ms as i64)
        } else {
            None
        }
    } else {
        tok.parse::<i64>().ok()
    }
}

/// Slice `bytes[start..end]` as `&str`, assuming ASCII/known-valid content
/// (metric names, numeric tokens). Callers guarantee validity.
fn str_from(body: &str, start: usize, end: usize) -> &str {
    // The body is &str, so slices are valid UTF-8 by construction; the
    // O(1) boundary check replaces a full validation scan. Callers pass
    // offsets delimited by ASCII bytes, which are always char boundaries.
    body.get(start..end).unwrap_or("")
}

/// Slice `bytes[start..end]` as `&str`, returning a parse error on invalid
/// UTF-8. Used for label values, which may contain arbitrary UTF-8.
fn utf8_from(body: &str, start: usize, end: usize, line_no: usize) -> Result<&str, ParseError> {
    // O(1) boundary check; the body is already valid UTF-8.
    body.get(start..end)
        .ok_or_else(|| ParseError::new(line_no, "invalid UTF-8 boundary in label value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: i64 = 1_700_000_000_000;

    /// Find the value of `name` among a series' labels.
    fn label<'a>(ts: &'a TimeSeries, name: &str) -> Option<&'a str> {
        ts.labels
            .iter()
            .find(|l| l.name == name)
            .map(|l| l.value.as_str())
    }

    /// Convenience: metric name of a series.
    fn metric(ts: &TimeSeries) -> &str {
        label(ts, METRIC_NAME_LABEL).expect("series has a metric name")
    }

    #[test]
    fn realistic_scrape_body() -> Result<(), ParseError> {
        let body = "\
# HELP http_requests_total The total number of HTTP requests.
# TYPE http_requests_total counter
http_requests_total{method=\"post\",code=\"200\"} 1027 1395066363000
http_requests_total{method=\"post\",code=\"400\"}    3 1395066363000
# HELP node_load1 1m load average
# TYPE node_load1 gauge
node_load1 0.42
# TYPE request_duration_seconds histogram
request_duration_seconds_bucket{le=\"0.1\"} 24054
request_duration_seconds_bucket{le=\"0.5\"} 129389
request_duration_seconds_bucket{le=\"+Inf\"} 144320
request_duration_seconds_sum 53423
request_duration_seconds_count 144320
# TYPE rpc_duration_seconds summary
rpc_duration_seconds{quantile=\"0.5\"} 4773
rpc_duration_seconds{quantile=\"0.99\"} 76656
rpc_duration_seconds_sum 1.7560473e+07
rpc_duration_seconds_count 2693
";
        let series = parse(body, TS, true)?;
        assert_eq!(series.len(), 12);

        // First line: labels ordered __name__, method, code.
        let first = &series[0];
        assert_eq!(
            first
                .labels
                .iter()
                .map(|l| l.name.as_str())
                .collect::<Vec<_>>(),
            vec!["__name__", "method", "code"]
        );
        assert_eq!(metric(first), "http_requests_total");
        assert_eq!(label(first, "method"), Some("post"));
        assert_eq!(label(first, "code"), Some("200"));
        assert!((first.sample.value - 1027.0).abs() < f64::EPSILON);
        assert_eq!(first.sample.timestamp, 1_395_066_363_000);

        // Gauge with no labels and a default timestamp.
        let load = series
            .iter()
            .find(|s| metric(s) == "node_load1")
            .expect("load series");
        assert_eq!(load.labels.len(), 1);
        assert_eq!(load.sample.timestamp, TS);
        assert!((load.sample.value - 0.42).abs() < 1e-9);

        // +Inf bucket.
        let inf = series
            .iter()
            .find(|s| label(s, "le") == Some("+Inf"))
            .expect("inf bucket");
        assert!((inf.sample.value - 144_320.0).abs() < f64::EPSILON);

        // Scientific notation sum.
        let sum = series
            .iter()
            .find(|s| metric(s) == "rpc_duration_seconds_sum")
            .expect("rpc sum");
        assert!((sum.sample.value - 1.756_047_3e7).abs() < 1.0);

        Ok(())
    }

    #[test]
    fn escapes_in_label_values() -> Result<(), ParseError> {
        let body = r#"metric{a="back\\slash",b="quote\"here",c="new\nline"} 1"#;
        let series = parse(body, TS, true)?;
        assert_eq!(series.len(), 1);
        let s = &series[0];
        assert_eq!(label(s, "a"), Some("back\\slash"));
        assert_eq!(label(s, "b"), Some("quote\"here"));
        assert_eq!(label(s, "c"), Some("new\nline"));
        Ok(())
    }

    #[test]
    fn utf8_and_special_chars_in_values() -> Result<(), ParseError> {
        let body = "metric{a=\"héllo→世界\",b=\"has{brace}and,comma and space\"} 1";
        let series = parse(body, TS, true)?;
        let s = &series[0];
        assert_eq!(label(s, "a"), Some("héllo→世界"));
        assert_eq!(label(s, "b"), Some("has{brace}and,comma and space"));
        Ok(())
    }

    #[test]
    fn no_labels_empty_braces_and_trailing_comma() -> Result<(), ParseError> {
        let s1 = parse("metric 5", TS, true)?;
        assert_eq!(s1[0].labels.len(), 1);

        let s2 = parse("metric{} 5", TS, true)?;
        assert_eq!(s2[0].labels.len(), 1);

        let s3 = parse("metric{a=\"b\",} 5", TS, true)?;
        assert_eq!(s3[0].labels.len(), 2);
        assert_eq!(label(&s3[0], "a"), Some("b"));

        // Empty label value.
        let s4 = parse("metric{a=\"\"} 5", TS, true)?;
        assert_eq!(label(&s4[0], "a"), Some(""));
        Ok(())
    }

    #[test]
    fn value_forms() -> Result<(), ParseError> {
        let cases = [
            ("m 5", 5.0),
            ("m 5.5", 5.5),
            ("m -3", -3.0),
            ("m 1.5e3", 1500.0),
            ("m 1.5E-3", 0.0015),
            ("m +Inf", f64::INFINITY),
            ("m Inf", f64::INFINITY),
            ("m +inf", f64::INFINITY),
            ("m -Inf", f64::NEG_INFINITY),
        ];
        for (body, expected) in cases {
            let s = parse(body, TS, true)?;
            let got = s[0].sample.value;
            let ok = if expected.is_infinite() {
                got.is_infinite() && got.is_sign_positive() == expected.is_sign_positive()
            } else {
                (got - expected).abs() < 1e-9
            };
            assert!(ok, "body {body:?}: got {got}, expected {expected}");
        }

        // NaN case variants: check they parse to NaN.
        for body in ["m NaN", "m nan", "m NAN"] {
            let s = parse(body, TS, true)?;
            assert!(s[0].sample.value.is_nan(), "body {body:?} should be NaN");
        }
        Ok(())
    }

    #[test]
    fn timestamps() -> Result<(), ParseError> {
        // Present milliseconds.
        let s = parse("m 1 1395066363000", TS, true)?;
        assert_eq!(s[0].sample.timestamp, 1_395_066_363_000);

        // Absent: default used.
        let s = parse("m 1", TS, true)?;
        assert_eq!(s[0].sample.timestamp, TS);

        // Negative.
        let s = parse("m 1 -1000", TS, true)?;
        assert_eq!(s[0].sample.timestamp, -1000);

        // OpenMetrics float seconds -> ms.
        let s = parse("m 1 1.5", TS, true)?;
        assert_eq!(s[0].sample.timestamp, 1500);

        let s = parse("m 1 1395066363.123", TS, true)?;
        assert_eq!(s[0].sample.timestamp, 1_395_066_363_123);

        // Scientific-notation seconds.
        let s = parse("m 1 1.5e0", TS, true)?;
        assert_eq!(s[0].sample.timestamp, 1500);

        Ok(())
    }

    #[test]
    fn honor_timestamps_false_forces_default() -> Result<(), ParseError> {
        let s = parse("m 1 1395066363000", TS, false)?;
        assert_eq!(s[0].sample.timestamp, TS);

        let s = parse("m 1", TS, false)?;
        assert_eq!(s[0].sample.timestamp, TS);
        Ok(())
    }

    #[test]
    fn exemplar_suffix_ignored() -> Result<(), ParseError> {
        // Exemplar after value.
        let s = parse("m 1 # {trace_id=\"abc\"} 1.0", TS, true)?;
        assert!((s[0].sample.value - 1.0).abs() < f64::EPSILON);
        assert_eq!(s[0].sample.timestamp, TS);

        // Exemplar after value + timestamp.
        let s = parse("m 1 1500 # {trace_id=\"abc\"} 1.0 1520", TS, true)?;
        assert_eq!(s[0].sample.timestamp, 1500);
        Ok(())
    }

    #[test]
    fn empty_and_comment_only_bodies() -> Result<(), ParseError> {
        assert!(parse("", TS, true)?.is_empty());
        assert!(parse("   \n\t\n  \n", TS, true)?.is_empty());
        assert!(parse("# HELP x\n# TYPE x counter\n", TS, true)?.is_empty());
        // Indented comment.
        assert!(parse("   # a comment\n", TS, true)?.is_empty());
        Ok(())
    }

    #[test]
    fn openmetrics_eof_skipped() -> Result<(), ParseError> {
        let s = parse("m 1\n# EOF\n", TS, true)?;
        assert_eq!(s.len(), 1);
        Ok(())
    }

    #[test]
    fn crlf_line_endings() -> Result<(), ParseError> {
        let s = parse("m 1\r\nn 2\r\n", TS, true)?;
        assert_eq!(s.len(), 2);
        assert_eq!(metric(&s[0]), "m");
        assert_eq!(metric(&s[1]), "n");
        Ok(())
    }

    #[test]
    fn metric_name_with_colon() -> Result<(), ParseError> {
        let s = parse("my:custom:metric 1", TS, true)?;
        assert_eq!(metric(&s[0]), "my:custom:metric");
        Ok(())
    }

    #[test]
    fn whitespace_tolerance() -> Result<(), ParseError> {
        let s = parse("m { a = \"b\" , c = \"d\" }  5  1500", TS, true)?;
        assert_eq!(label(&s[0], "a"), Some("b"));
        assert_eq!(label(&s[0], "c"), Some("d"));
        assert_eq!(s[0].sample.timestamp, 1500);
        Ok(())
    }

    // --- error cases ---

    fn err_line(body: &str) -> usize {
        parse(body, TS, true).expect_err("should fail").line()
    }

    #[test]
    fn error_bad_metric_name() {
        assert!(parse("1metric 5", TS, true).is_err());
        assert!(parse("@metric 5", TS, true).is_err());
    }

    #[test]
    fn error_bad_label_name() {
        assert!(parse("m{1a=\"b\"} 5", TS, true).is_err());
        assert!(parse("m{a-b=\"c\"} 5", TS, true).is_err());
    }

    #[test]
    fn error_unterminated_quote() {
        assert!(parse("m{a=\"b} 5", TS, true).is_err());
        assert!(parse("m{a=\"b\\\"} 5", TS, true).is_err());
    }

    #[test]
    fn error_bad_escape() {
        assert!(parse(r#"m{a="b\tc"} 5"#, TS, true).is_err());
        assert!(parse(r#"m{a="b\xc"} 5"#, TS, true).is_err());
    }

    #[test]
    fn error_duplicate_label() {
        let e = parse("m{a=\"1\",a=\"2\"} 5", TS, true).expect_err("dup");
        assert!(
            e.message().contains("duplicate"),
            "message: {}",
            e.message()
        );
    }

    #[test]
    fn error_name_label_in_braces() {
        let e = parse("m{__name__=\"x\"} 5", TS, true).expect_err("name in braces");
        assert!(e.message().contains("__name__"), "message: {}", e.message());
    }

    #[test]
    fn error_missing_value() {
        assert!(parse("m", TS, true).is_err());
        assert!(parse("m{a=\"b\"}", TS, true).is_err());
        assert!(parse("m   ", TS, true).is_err());
    }

    #[test]
    fn error_bad_value() {
        assert!(parse("m notanumber", TS, true).is_err());
        assert!(parse("m 5x", TS, true).is_err());
    }

    #[test]
    fn error_garbage_after_timestamp() {
        // Non-exemplar trailing content is an error.
        assert!(parse("m 1 1500 garbage", TS, true).is_err());
    }

    #[test]
    fn error_bad_timestamp() {
        assert!(parse("m 1 notanumber", TS, true).is_err());
    }

    #[test]
    fn error_missing_equals() {
        assert!(parse("m{a \"b\"} 5", TS, true).is_err());
        assert!(parse("m{a} 5", TS, true).is_err());
    }

    #[test]
    fn error_line_number_is_reported() {
        // Third line is malformed.
        let body = "m 1\nn 2\n@bad 3\n";
        assert_eq!(err_line(body), 3);
    }

    #[test]
    fn error_display_format() {
        let e = ParseError::new(17, "something broke");
        assert_eq!(e.to_string(), "line 17: something broke");
    }

    #[test]
    fn unterminated_label_set() {
        assert!(parse("m{a=\"b\"", TS, true).is_err());
        assert!(parse("m{a=\"b\",", TS, true).is_err());
        assert!(parse("m{", TS, true).is_err());
    }
}
