//! Prometheus relabeling (`relabel_configs` / `metric_relabel_configs`).
//!
//! Semantics follow `model/relabel/relabel.go` from the Prometheus repository.

use md5::{
    Digest,
    Md5,
};
use serde::Deserialize;

use crate::model::Label;

/// A single relabeling rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RelabelConfig {
    pub source_labels: Vec<String>,
    pub separator: String,
    pub target_label: String,
    pub regex: AnchoredRegex,
    pub modulus: u64,
    pub replacement: String,
    pub action: Action,
}

impl Default for RelabelConfig {
    fn default() -> Self {
        Self {
            source_labels: Vec::new(),
            separator: ";".to_owned(),
            target_label: String::new(),
            regex: AnchoredRegex::default(),
            modulus: 0,
            replacement: "$1".to_owned(),
            action: Action::Replace,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Replace,
    Keep,
    Drop,
    KeepEqual,
    DropEqual,
    HashMod,
    LabelMap,
    LabelDrop,
    LabelKeep,
    Lowercase,
    Uppercase,
}

/// A regex that is fully anchored (`^(?:...)$`) like Prometheus relabel
/// regexes.
#[derive(Debug, Clone)]
pub struct AnchoredRegex {
    /// The original pattern as written in the config.
    pub source: String,
    pub regex: regex::Regex,
}

impl AnchoredRegex {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            source: pattern.to_owned(),
            regex: regex::Regex::new(&format!("^(?:{pattern})$"))?,
        })
    }
}

impl RelabelConfig {
    /// Validate that this config is internally consistent.
    ///
    /// Mirrors the essential checks from Prometheus'
    /// `RelabelConfig.Validate`. Returns a human-readable error string on
    /// failure.
    pub fn validate(&self) -> Result<(), String> {
        match self.action {
            Action::HashMod => {
                if self.modulus == 0 {
                    return Err("relabel action hashmod requires modulus > 0".to_owned());
                }
                if self.target_label.is_empty() {
                    return Err("relabel action hashmod requires target_label".to_owned());
                }
            }
            Action::Replace
            | Action::Lowercase
            | Action::Uppercase
            | Action::KeepEqual
            | Action::DropEqual => {
                if self.target_label.is_empty() {
                    return Err(format!(
                        "relabel action {:?} requires target_label",
                        self.action
                    ));
                }
            }
            Action::Keep
            | Action::Drop
            | Action::LabelMap
            | Action::LabelDrop
            | Action::LabelKeep => {}
        }
        Ok(())
    }
}

impl Default for AnchoredRegex {
    fn default() -> Self {
        #[expect(clippy::unwrap_used, reason = "static pattern is known valid")]
        Self::new("(.*)").unwrap()
    }
}

impl<'de> Deserialize<'de> for AnchoredRegex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let pattern = String::deserialize(deserializer)?;
        Self::new(&pattern).map_err(serde::de::Error::custom)
    }
}

/// Apply `configs` in order to `labels`.
///
/// Returns `None` when the series is dropped by a `keep`/`drop`/`keepequal`/
/// `dropequal` rule. Labels with empty values are removed afterwards.
#[must_use]
pub fn process(labels: Vec<Label>, configs: &[RelabelConfig]) -> Option<Vec<Label>> {
    let mut set = LabelSet::from(labels);
    // Reused buffer for the joined `source_labels` value.
    let mut val = String::new();
    for config in configs {
        if !apply(&mut set, config, &mut val) {
            return None;
        }
    }
    let mut labels = set.into_labels();
    // Prometheus' label builder drops any label with an empty value.
    labels.retain(|label| !label.value.is_empty());
    Some(labels)
}

/// Working label set: unique names, order-insensitive linear scans.
///
/// Label sets are small, so a `Vec` with linear scans beats a map on both
/// allocations and constant factors.
#[derive(Debug)]
struct LabelSet {
    labels: Vec<Label>,
}

impl From<Vec<Label>> for LabelSet {
    fn from(labels: Vec<Label>) -> Self {
        Self { labels }
    }
}

impl LabelSet {
    fn get(&self, name: &str) -> &str {
        self.labels
            .iter()
            .find(|label| label.name == name)
            .map_or("", |label| label.value.as_str())
    }

    /// Set `name` to `value`, overwriting any existing label of that name.
    fn set(&mut self, name: &str, value: String) {
        if let Some(label) = self.labels.iter_mut().find(|label| label.name == name) {
            label.value = value;
        } else {
            self.labels.push(Label::new(name.to_owned(), value));
        }
    }

    fn remove(&mut self, name: &str) {
        self.labels.retain(|label| label.name != name);
    }

    /// Join the values of `source_labels` with `separator` into `buf`.
    ///
    /// A missing label contributes the empty string. `buf` is cleared first
    /// and returned for use by the caller.
    fn join<'a>(&self, source_labels: &[String], separator: &str, buf: &'a mut String) -> &'a str {
        buf.clear();
        for (i, name) in source_labels.iter().enumerate() {
            if i > 0 {
                buf.push_str(separator);
            }
            buf.push_str(self.get(name));
        }
        buf
    }

    fn into_labels(self) -> Vec<Label> {
        self.labels
    }
}

/// Apply a single config to `set`.
///
/// Returns `false` when the series should be dropped, `true` otherwise.
fn apply(set: &mut LabelSet, config: &RelabelConfig, val: &mut String) -> bool {
    let re = &config.regex.regex;
    match config.action {
        Action::Replace => {
            apply_replace(set, config, val);
        }
        Action::Keep => {
            let joined = set.join(&config.source_labels, &config.separator, val);
            if !re.is_match(joined) {
                return false;
            }
        }
        Action::Drop => {
            let joined = set.join(&config.source_labels, &config.separator, val);
            if re.is_match(joined) {
                return false;
            }
        }
        Action::KeepEqual => {
            let joined = set.join(&config.source_labels, &config.separator, val);
            if joined != set.get(&config.target_label) {
                return false;
            }
        }
        Action::DropEqual => {
            let joined = set.join(&config.source_labels, &config.separator, val);
            if joined == set.get(&config.target_label) {
                return false;
            }
        }
        Action::HashMod => {
            let joined = set.join(&config.source_labels, &config.separator, val);
            let hash = hash_mod(joined, config.modulus);
            set.set(&config.target_label, hash.to_string());
        }
        Action::LabelMap => {
            // Collect first: we mutate `set` while iterating over matches.
            let mut updates: Vec<(String, String)> = Vec::new();
            for label in &set.labels {
                if let Some(caps) = re.captures(&label.name) {
                    let mut name = String::new();
                    caps.expand(&config.replacement, &mut name);
                    updates.push((name, label.value.clone()));
                }
            }
            for (name, value) in updates {
                set.set(&name, value);
            }
        }
        Action::LabelDrop => {
            set.labels.retain(|label| !re.is_match(&label.name));
        }
        Action::LabelKeep => {
            set.labels.retain(|label| re.is_match(&label.name));
        }
        Action::Lowercase => {
            let joined = set.join(&config.source_labels, &config.separator, val);
            let lowered = joined.to_lowercase();
            set.set(&config.target_label, lowered);
        }
        Action::Uppercase => {
            let joined = set.join(&config.source_labels, &config.separator, val);
            let uppered = joined.to_uppercase();
            set.set(&config.target_label, uppered);
        }
    }
    true
}

/// The `replace` action, split out of [`apply`] for readability.
fn apply_replace(set: &mut LabelSet, config: &RelabelConfig, val: &mut String) {
    let joined = set.join(&config.source_labels, &config.separator, val);
    // Fast path for the ubiquitous `source -> target_label` copy rule:
    // the default regex `(.*)` always matches (and captures the whole
    // value) unless the value contains a newline, and simple
    // replacements need no capture expansion. Operator-generated
    // configs consist almost entirely of such rules; this skips the
    // regex engine and its per-call captures allocation.
    if config.regex.source == "(.*)" && !config.target_label.contains('$') {
        if joined.contains('\n') {
            // `.` does not match newlines: the anchored default regex
            // would not match, leaving the label set untouched.
            return;
        }
        let value = if config.replacement == "$1" || config.replacement == "${1}" {
            Some(joined.to_owned())
        } else if !config.replacement.contains('$') {
            Some(config.replacement.clone())
        } else {
            None // exotic replacement: general path below
        };
        if let Some(value) = value {
            if !is_valid_label_name(&config.target_label) {
                return;
            }
            if value.is_empty() {
                set.remove(&config.target_label);
            } else {
                set.set(&config.target_label, value);
            }
            return;
        }
    }
    // No match leaves the label set untouched.
    let Some(caps) = config.regex.regex.captures(joined) else {
        return;
    };
    let mut target = String::new();
    caps.expand(&config.target_label, &mut target);
    if !is_valid_label_name(&target) {
        return;
    }
    let mut replacement = String::new();
    caps.expand(&config.replacement, &mut replacement);
    if replacement.is_empty() {
        set.remove(&target);
    } else {
        set.set(&target, replacement);
    }
}

/// MD5-hash `val` and reduce it modulo `modulus`, matching Prometheus:
/// `binary.BigEndian.Uint64(md5.Sum(val)[8:]) % modulus`.
fn hash_mod(val: &str, modulus: u64) -> u64 {
    let digest = Md5::digest(val.as_bytes());
    // Bytes 8..16 of the 16-byte digest, big-endian.
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[8..16]);
    let hash = u64::from_be_bytes(bytes);
    hash % modulus
}

/// Whether `name` matches Prometheus' valid label name syntax
/// `[a-zA-Z_][a-zA-Z0-9_]*`.
fn is_valid_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::{
        Action,
        AnchoredRegex,
        RelabelConfig,
        process,
    };
    use crate::model::Label;

    /// Build a label set from `(name, value)` pairs.
    fn labels(pairs: &[(&str, &str)]) -> Vec<Label> {
        pairs
            .iter()
            .map(|(name, value)| Label::new(*name, *value))
            .collect()
    }

    /// Build a config, defaulting the fields a caller does not care about.
    fn config(action: Action) -> RelabelConfig {
        RelabelConfig {
            action,
            ..RelabelConfig::default()
        }
    }

    /// Look up a label value, returning `None` when absent.
    fn get<'a>(labels: &'a [Label], name: &str) -> Option<&'a str> {
        labels
            .iter()
            .find(|label| label.name == name)
            .map(|label| label.value.as_str())
    }

    /// Assert two label sets are equal ignoring order.
    fn assert_labels_eq(mut got: Vec<Label>, mut want: Vec<Label>) {
        got.sort_by(|a, b| a.name.cmp(&b.name));
        want.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got, want);
    }

    #[test]
    fn fast_path_matches_general_path_semantics() {
        // default regex, $1 replacement: copies joined value
        let mut copy = config(Action::Replace);
        copy.source_labels = vec!["a".to_owned()];
        copy.target_label = "copy".to_owned();
        let out = process(labels(&[("a", "v1")]), std::slice::from_ref(&copy)).expect("kept");
        assert_eq!(get(&out, "copy"), Some("v1"));

        // default regex, literal replacement
        let mut lit = copy.clone();
        lit.target_label = "lit".to_owned();
        lit.replacement = "fixed".to_owned();
        let out = process(labels(&[("a", "v1")]), std::slice::from_ref(&lit)).expect("kept");
        assert_eq!(get(&out, "lit"), Some("fixed"));

        // newline in value: default anchored regex does not match -> unchanged
        let out =
            process(labels(&[("a", "v\n1")]), std::slice::from_ref(&copy)).expect("kept");
        assert_eq!(get(&out, "copy"), None);

        // empty joined value deletes the target label (matches general path)
        let mut wipe = config(Action::Replace);
        wipe.source_labels = vec!["missing".to_owned()];
        wipe.target_label = "gone".to_owned();
        let out = process(
            labels(&[("gone", "was-here"), ("keep", "x")]),
            std::slice::from_ref(&wipe),
        )
        .expect("kept");
        assert_eq!(get(&out, "gone"), None);
        assert_eq!(get(&out, "keep"), Some("x"));
    }

    #[test]
    fn replace_with_capture_group() {
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            regex: AnchoredRegex::new("f(.*)").unwrap(),
            target_label: "d".to_owned(),
            replacement: "ch${1}-ch${1}".to_owned(),
            ..config(Action::Replace)
        };
        let out = process(labels(&[("a", "foo")]), &[cfg]).unwrap();
        assert_eq!(get(&out, "d"), Some("choo-choo"));
        assert_eq!(get(&out, "a"), Some("foo"));
    }

    #[test]
    fn replace_templated_target_label() {
        // The target label name itself is templated from a capture group.
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            regex: AnchoredRegex::new("(.*)").unwrap(),
            target_label: "${1}".to_owned(),
            replacement: "value".to_owned(),
            ..config(Action::Replace)
        };
        let out = process(labels(&[("a", "boo")]), &[cfg]).unwrap();
        assert_eq!(get(&out, "boo"), Some("value"));
    }

    #[test]
    fn replace_no_match_leaves_labels_untouched() {
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            regex: AnchoredRegex::new("o(.*)a").unwrap(),
            target_label: "d".to_owned(),
            replacement: "${1}".to_owned(),
            ..config(Action::Replace)
        };
        let out = process(labels(&[("a", "foo")]), &[cfg]).unwrap();
        assert_labels_eq(out, labels(&[("a", "foo")]));
    }

    #[test]
    fn replace_empty_value_deletes_target() {
        // Replacement expands to empty -> the target label is removed.
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            regex: AnchoredRegex::new("(.*)").unwrap(),
            target_label: "b".to_owned(),
            replacement: "${2}".to_owned(),
            ..config(Action::Replace)
        };
        let out = process(labels(&[("a", "foo"), ("b", "bar")]), &[cfg]).unwrap();
        assert_eq!(get(&out, "b"), None);
        assert_eq!(get(&out, "a"), Some("foo"));
    }

    #[test]
    fn replace_invalid_target_label_no_change() {
        // Expanded target "0abc" is not a valid label name.
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            regex: AnchoredRegex::new("(.*)").unwrap(),
            target_label: "0${1}".to_owned(),
            replacement: "x".to_owned(),
            ..config(Action::Replace)
        };
        let out = process(labels(&[("a", "foo")]), &[cfg]).unwrap();
        assert_labels_eq(out, labels(&[("a", "foo")]));
    }

    #[test]
    fn keep_with_separator() {
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned(), "b".to_owned()],
            separator: ";".to_owned(),
            regex: AnchoredRegex::new("foo;bar").unwrap(),
            ..config(Action::Keep)
        };
        assert!(
            process(
                labels(&[("a", "foo"), ("b", "bar")]),
                std::slice::from_ref(&cfg)
            )
            .is_some()
        );
        assert!(process(labels(&[("a", "foo"), ("b", "baz")]), &[cfg]).is_none());
    }

    #[test]
    fn drop_with_separator() {
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned(), "b".to_owned()],
            separator: ";".to_owned(),
            regex: AnchoredRegex::new("foo;bar").unwrap(),
            ..config(Action::Drop)
        };
        assert!(
            process(
                labels(&[("a", "foo"), ("b", "bar")]),
                std::slice::from_ref(&cfg)
            )
            .is_none()
        );
        assert!(process(labels(&[("a", "foo"), ("b", "baz")]), &[cfg]).is_some());
    }

    #[test]
    fn keepequal() {
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            target_label: "b".to_owned(),
            ..config(Action::KeepEqual)
        };
        assert!(
            process(
                labels(&[("a", "x"), ("b", "x")]),
                std::slice::from_ref(&cfg)
            )
            .is_some()
        );
        assert!(process(labels(&[("a", "x"), ("b", "y")]), &[cfg]).is_none());
    }

    #[test]
    fn dropequal() {
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            target_label: "b".to_owned(),
            ..config(Action::DropEqual)
        };
        assert!(
            process(
                labels(&[("a", "x"), ("b", "x")]),
                std::slice::from_ref(&cfg)
            )
            .is_none()
        );
        assert!(process(labels(&[("a", "x"), ("b", "y")]), &[cfg]).is_some());
    }

    #[test]
    fn hashmod_known_value() {
        // {a="foo"} source [a] modulus 1000.
        //
        // MD5("foo") = acbd18db4cc2f85cedef654fccc4a4d8; bytes [8..16] as a
        // big-endian u64 = 0xedef654fccc4a4d8; that mod 1000 = 696. (The
        // "976" figure floated in the task brief does not match this exact
        // input/modulus; 696 is what the documented algorithm produces and is
        // verified above by hand.)
        let cfg = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            target_label: "d".to_owned(),
            modulus: 1000,
            ..config(Action::HashMod)
        };
        let out = process(labels(&[("a", "foo")]), &[cfg]).unwrap();
        assert_eq!(get(&out, "d"), Some("696"));
    }

    #[test]
    fn labelmap() {
        let cfg = RelabelConfig {
            regex: AnchoredRegex::new("__meta_(.*)").unwrap(),
            replacement: "flag_${1}".to_owned(),
            ..config(Action::LabelMap)
        };
        let out = process(labels(&[("__meta_foo", "bar")]), &[cfg]).unwrap();
        assert_eq!(get(&out, "flag_foo"), Some("bar"));
        // The original label survives.
        assert_eq!(get(&out, "__meta_foo"), Some("bar"));
    }

    #[test]
    fn labeldrop() {
        let cfg = RelabelConfig {
            regex: AnchoredRegex::new("__.*").unwrap(),
            ..config(Action::LabelDrop)
        };
        let out = process(labels(&[("__internal", "x"), ("keep", "y")]), &[cfg]).unwrap();
        assert_eq!(get(&out, "__internal"), None);
        assert_eq!(get(&out, "keep"), Some("y"));
    }

    #[test]
    fn labelkeep() {
        let cfg = RelabelConfig {
            regex: AnchoredRegex::new("keep.*").unwrap(),
            ..config(Action::LabelKeep)
        };
        let out = process(labels(&[("__internal", "x"), ("keep_me", "y")]), &[cfg]).unwrap();
        assert_eq!(get(&out, "__internal"), None);
        assert_eq!(get(&out, "keep_me"), Some("y"));
    }

    #[test]
    fn lowercase_and_uppercase() {
        let lower = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            target_label: "b".to_owned(),
            ..config(Action::Lowercase)
        };
        let out = process(labels(&[("a", "MixedCase")]), &[lower]).unwrap();
        assert_eq!(get(&out, "b"), Some("mixedcase"));

        let upper = RelabelConfig {
            source_labels: vec!["a".to_owned()],
            target_label: "b".to_owned(),
            ..config(Action::Uppercase)
        };
        let out = process(labels(&[("a", "MixedCase")]), &[upper]).unwrap();
        assert_eq!(get(&out, "b"), Some("MIXEDCASE"));
    }

    #[test]
    fn chained_configs() {
        // First map __address__ into instance, then drop the __ label.
        let map = RelabelConfig {
            source_labels: vec!["__address__".to_owned()],
            regex: AnchoredRegex::new("(.*)").unwrap(),
            target_label: "instance".to_owned(),
            replacement: "${1}".to_owned(),
            ..config(Action::Replace)
        };
        let drop_meta = RelabelConfig {
            regex: AnchoredRegex::new("__.*").unwrap(),
            ..config(Action::LabelDrop)
        };
        let out = process(
            labels(&[("__address__", "host:9090"), ("job", "node")]),
            &[map, drop_meta],
        )
        .unwrap();
        assert_eq!(get(&out, "instance"), Some("host:9090"));
        assert_eq!(get(&out, "__address__"), None);
        assert_eq!(get(&out, "job"), Some("node"));
    }

    #[test]
    fn final_empty_value_labels_removed() {
        // An explicitly empty label is stripped by the final pass.
        let out = process(labels(&[("a", "foo"), ("empty", "")]), &[]).unwrap();
        assert_eq!(get(&out, "empty"), None);
        assert_eq!(get(&out, "a"), Some("foo"));
    }

    #[test]
    fn validate_hashmod_requires_modulus_and_target() {
        let mut cfg = config(Action::HashMod);
        cfg.target_label = "d".to_owned();
        assert!(cfg.validate().is_err());
        cfg.modulus = 1;
        assert!(cfg.validate().is_ok());
        cfg.target_label = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_replace_requires_target() {
        let cfg = config(Action::Replace);
        assert!(cfg.validate().is_err());
        let cfg = RelabelConfig {
            target_label: "d".to_owned(),
            ..config(Action::Replace)
        };
        assert!(cfg.validate().is_ok());
    }
}
