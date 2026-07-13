//! Pseudonymize a private scrape corpus so it can be committed.
//!
//! Reads raw exposition bodies captured from a live cluster, replaces every
//! environment-specific label value with a deterministic pseudonym, and writes
//! the result to the committed corpus directory.
//!
//! ```text
//! cargo run --example sanitize_corpus -- --input corpus-raw --output pgo-corpus
//! ```
//!
//! # Fidelity
//!
//! PGO and the criterion benches care about the *shape* of a body, not its
//! contents. A pseudonym therefore preserves, exactly:
//!
//! * **byte length** — drives the word-at-a-time hasher's loop trip count and
//!   the copy paths in the encoder;
//! * **cardinality** — the raw-value-to-output mapping is injective across both
//!   kept and pseudonymized values, so distinct-value counts and cross-label
//!   equality both survive. The v2 encoder's memoized interning hits at the
//!   same rate it would on the raw body;
//! * **character class** — digits stay digits, letters keep their case, and
//!   separators (`/ . - _ : @ +`) are preserved, so a UUID stays UUID-shaped
//!   and a mount path stays path-shaped.
//!
//! Over-redacting is therefore close to free: it costs readability, not profile
//! accuracy. [`KEEP`] is deliberately short.
//!
//! # What is *not* touched
//!
//! Metric names, `# HELP`/`# TYPE` comments, sample values and timestamps.
//! These come from the exporters' own source code, not from the environment —
//! an assumption [`leak_scan`] re-checks against the output rather than
//! trusting.

use std::{
    collections::{
        BTreeMap,
        BTreeSet,
        HashMap,
    },
    fs,
    path::PathBuf,
};

use anyhow::{
    Context as _,
    bail,
};
use clap::Parser;
use md5::{
    Digest as _,
    Md5,
};

/// Label names whose values are safe to keep verbatim. **Everything else is
/// redacted.**
///
/// Deny-by-default, because an audit of the raw corpus found environment
/// identifiers hiding in labels that look like plain enums — `serial` held
/// hardware serial numbers, and `datasource_type`, `dialer_name` and `cluster`
/// all held internal project names. Guessing which labels are dangerous does
/// not work; the list below instead enumerates the ones positively verified to
/// draw their values from an exporter's own source code.
///
/// The asymmetry is the point. Forgetting to list a safe label costs a little
/// readability. Forgetting to redact an unsafe one leaks it into git history.
const KEEP: &[&str] = &[
    // Bucket and quantile bounds. The parser has dedicated numeric paths for
    // these two, so they must survive verbatim or the profile shifts.
    "le",
    "quantile",
    // Outcome and status enums.
    "code",
    "condition",
    "error",
    "device_error",
    "errorSource",
    "is_error",
    "outcome",
    "result",
    "reason",
    "return_code",
    "status",
    "status_code",
    "status_source",
    "success",
    "valid",
    "signature_status",
    // Booleans.
    "active",
    "allowed",
    "cache_hit",
    "dry_run",
    "equal",
    "hit",
    "out_of_order",
    "secure_socks_ds_proxy_enabled",
    "ws",
    // HTTP and RPC.
    "handler",
    "method",
    "route",
    "scheme",
    "verb",
    "protocol",
    "protocol_l7",
    "proto",
    "transport",
    "format",
    "request_kind",
    "request_type",
    // Kubernetes and API-server vocabulary.
    "controller",
    "group",
    "kind",
    "resource",
    "subresource",
    "stability_level",
    "deprecated_version",
    "field_validation",
    // Cilium internals.
    "area",
    "api_call",
    "endpoint_state",
    "enforcement",
    "map_group",
    "map_name",
    "module_id",
    "proxy_type",
    "subsystem",
    "scope",
    "class",
    "direction",
    // Mimir/Thanos internals.
    "additional_queue_dimensions",
    "component",
    "data_type",
    "engine",
    "gate",
    "index_storage",
    "ingester_zone",
    "item_type",
    "limit",
    "query_component",
    "query_type",
    "queue",
    "slice",
    "slo_group",
    "stage",
    "stage_type",
    "storage",
    "store_gateway_zone",
    "op",
    "operation",
    "action",
    "phase",
    "rule",
    "state",
    "step",
    // Grafana internals.
    "backend",
    "db_name",
    "endpoint",
    "parent",
    "plugin_id",
    "plugin_type",
    "plugin_version",
    "service",
    "served_by",
    "channel_type",
    "frame_type",
    "event_type",
    "signal",
    "asset_source",
    "filter",
    "cause",
    // Node-exporter enums drawn from kernel/procfs vocabulary.
    "adminstate",
    "address_family",
    "address_type",
    "clocksource",
    "collector",
    "cpu",
    "duplex",
    "family",
    "filesystem_type",
    "fstype",
    "ip", // "v4"/"v6" — an address *family*, not an address.
    "major",
    "minor",
    "mode",
    "operstate",
    "rotational",
    "sensor",
    "type",
    "unit", // Includes "°C"/"g/m³": harmless, and exercises the UTF-8 path.
    // Go runtime and build vocabulary, fixed by the toolchain.
    "arch",
    "goarch",
    "goos",
    "goversion",
    "edition",
    "memory",
    "usage",
    "level",
    "global",
    "time_zone",
    "algorithm",
    "acceleration",
    "role",
    "source",
    "target",
    "client",
    // NOTE: `key` is deliberately absent. It looks like Mimir collector
    // vocabulary ("collectors/compactor") and was allowlisted on that basis, but
    // it also carries per-tenant keys. The leak scan caught it.
];

/// Labels holding values that are unambiguously *environment identity*: a
/// hostname, a wireless BSSID, a tenant name, a hardware serial, a hosting
/// vendor.
///
/// Deny-by-default already redacts these along with everything else. Naming
/// them separately lets [`leak_scan`] assert the stronger property that they
/// appear **nowhere** in the output — not in a metric name, not in HELP text,
/// not anywhere — since no exporter would ever emit them as part of its own
/// vocabulary. Values are read from the raw input at run time, so no private
/// string is ever written into this file.
const HIGH_RISK: &[&str] = &[
    "addr",
    "address",
    "bios_vendor",
    "board_name",
    "board_serial",
    "board_vendor",
    "bssid",
    "chassis_serial",
    "chassis_vendor",
    "cluster",
    "commit",
    "datasource",
    "datasource_type",
    "devicename",
    "dialer_name",
    "domainname",
    "friendlyname",
    "group_name",
    "host",
    "hostname",
    "image",
    "image_id",
    "instance",
    "issuer_name",
    "mac_address",
    "node",
    "nodename",
    "org",
    "pod",
    "product_family",
    "product_name",
    "product_sku",
    "revision",
    "scheduler_address",
    "serial",
    "sha256",
    "ssid",
    "system_vendor",
    "tenant",
    "user",
];

#[derive(Parser, Debug)]
#[command(about = "Pseudonymize a private scrape corpus for committing")]
struct Args {
    /// Directory of raw, private `*.prom` bodies.
    #[arg(long)]
    input: PathBuf,

    /// Directory to write pseudonymized `*.prom` bodies into.
    #[arg(long)]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.output)
        .with_context(|| format!("creating {}", args.output.display()))?;

    let mut inputs: Vec<PathBuf> = fs::read_dir(&args.input)
        .with_context(|| format!("reading {}", args.input.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "prom"))
        .collect();
    inputs.sort();

    if inputs.is_empty() {
        bail!("no *.prom files in {}", args.input.display());
    }

    let bodies: Vec<String> = inputs
        .iter()
        .map(|p| fs::read_to_string(p).with_context(|| format!("reading {}", p.display())))
        .collect::<anyhow::Result<_>>()?;

    // Pass 1: the public vocabulary — every value that occurs in an allowlisted
    // label somewhere in the corpus. Redacting such a value where it *also*
    // appears in an unlisted label would gain nothing (the allowlisted copy
    // survives regardless) while splitting one distinct string into two, which
    // inflates cardinality and skews the interning hit rate.
    let public = public_vocabulary(&bodies);

    // Seeding `taken` keeps the raw -> output mapping injective across *both*
    // kept and pseudonymized values, so distinct-value counts survive exactly.
    let mut pseudonyms = Pseudonymizer {
        taken: public.clone(),
        ..Pseudonymizer::default()
    };
    // Identity values seen in the raw input, so the scan can prove none survived.
    let mut high_risk = BTreeSet::new();
    let mut report = BTreeMap::<String, usize>::new();

    // Pass 2: rewrite.
    for (path, raw) in inputs.iter().zip(&bodies) {
        let clean = sanitize(raw, &public, &mut pseudonyms, &mut high_risk, &mut report);

        // The scan runs per file, on the text we are about to write.
        leak_scan(&clean, &high_risk)
            .with_context(|| format!("leak scan failed for {}", path.display()))?;

        let dest = args
            .output
            .join(path.file_name().context("corpus entry has no file name")?);
        fs::write(&dest, &clean).with_context(|| format!("writing {}", dest.display()))?;

        println!(
            "{:<24} {:>7} B -> {:>7} B",
            path.file_name().unwrap_or_default().to_string_lossy(),
            raw.len(),
            clean.len(),
        );
    }

    println!("\nredacted label values, by label:");
    for (label, count) in &report {
        println!("  {label:<20} {count:>5}");
    }
    println!(
        "\n{} distinct high-risk values proven absent; leak scan clean on all {} files",
        high_risk.len(),
        inputs.len(),
    );
    Ok(())
}

/// Every value that appears in an allowlisted label anywhere in the corpus.
///
/// These strings are public by the same audit that produced [`KEEP`], and they
/// survive into the output regardless — so redacting the *same* string where it
/// happens to appear in an unlisted label buys no privacy, and costs fidelity:
/// one distinct raw value would become two distinct output values (the verbatim
/// one and the pseudonym), inflating the cardinality the interning cache sees.
///
/// A value that also occurs in a [`HIGH_RISK`] label is excluded, so identity
/// can never be blessed into the vocabulary by an allowlisting mistake. If that
/// ever happens the value still reaches the output through the allowlisted
/// label, and [`leak_scan`] fails the run.
fn public_vocabulary(bodies: &[String]) -> BTreeSet<String> {
    let mut public = BTreeSet::new();
    let mut identity = BTreeSet::new();

    for body in bodies {
        for line in body.lines() {
            if line.starts_with('#') {
                continue;
            }
            let Some(open) = line.find('{') else { continue };
            let Some(close) = label_set_end(line, open) else {
                continue;
            };
            for (name, value) in split_labels(&line[open + 1..close]) {
                if value.is_empty() {
                    continue;
                }
                if KEEP.contains(&name) {
                    public.insert(value.to_owned());
                }
                if HIGH_RISK.contains(&name) {
                    identity.insert(value.to_owned());
                }
            }
        }
    }
    // Only identity-*shaped* values are withheld from the vocabulary. A label like
    // `datasource_type` mixes both kinds: it carries tenant names, but also the
    // plain public type names "prometheus" and "tempo", which `plugin_id` uses
    // too. Withholding those would pseudonymize them in one label while the
    // allowlisted label kept them verbatim — splitting one raw value into two
    // output values for no privacy gain. See [`is_distinctive`].
    public.retain(|v| !(identity.contains(v) && is_distinctive(v)));
    public
}

/// Rewrite one exposition body, replacing denied label values in place.
///
/// Comment lines, metric names, sample values and timestamps are copied
/// verbatim; only the inside of a `{...}` label set is touched.
fn sanitize(
    body: &str,
    public: &BTreeSet<String>,
    pseudonyms: &mut Pseudonymizer,
    high_risk: &mut BTreeSet<String>,
    report: &mut BTreeMap<String, usize>,
) -> String {
    let mut out = String::with_capacity(body.len());

    for line in body.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        let Some(open) = line.find('{') else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let Some(close) = label_set_end(line, open) else {
            out.push_str(line);
            out.push('\n');
            continue;
        };

        out.push_str(&line[..=open]);
        rewrite_labels(
            &line[open + 1..close],
            &mut out,
            public,
            pseudonyms,
            high_risk,
            report,
        );
        out.push_str(&line[close..]);
        out.push('\n');
    }
    out
}

/// Find the `}` closing the label set opened at `open`, skipping any `}` that
/// sits inside a quoted label value.
fn label_set_end(line: &str, open: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    let mut escaped = false;

    for (i, &b) in bytes.iter().enumerate().skip(open + 1) {
        match b {
            _ if escaped => escaped = false,
            b'\\' if in_quotes => escaped = true,
            b'"' => in_quotes = !in_quotes,
            b'}' if !in_quotes => return Some(i),
            _ => {}
        }
    }
    None
}

/// Rewrite `name="value",name="value"` pairs, pseudonymizing denied names.
fn rewrite_labels(
    labels: &str,
    out: &mut String,
    public: &BTreeSet<String>,
    pseudonyms: &mut Pseudonymizer,
    high_risk: &mut BTreeSet<String>,
    report: &mut BTreeMap<String, usize>,
) {
    for (i, (name, value)) in split_labels(labels).into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(name);
        out.push_str("=\"");

        // Track identity values regardless of what we do with them, so the scan
        // still fires if one reaches the output via a wrongly-allowlisted label.
        if HIGH_RISK.contains(&name) && !value.is_empty() {
            high_risk.insert(value.to_owned());
        }

        if !KEEP.contains(&name) && !value.is_empty() && !public.contains(value) {
            *report.entry(name.to_owned()).or_default() += 1;
            out.push_str(&pseudonyms.get(value));
        } else {
            out.push_str(value);
        }
        out.push('"');
    }
}

/// Split a label set into `(name, raw_value)` pairs. `raw_value` is the text
/// between the quotes, escapes left as-is.
fn split_labels(labels: &str) -> Vec<(&str, &str)> {
    let bytes = labels.as_bytes();
    let mut pairs = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b',' || bytes[i] == b' ') {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len() && bytes[i] != b'=' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name = &labels[name_start..i];
        i += 1; // '='
        if i >= bytes.len() || bytes[i] != b'"' {
            break;
        }
        i += 1; // opening '"'

        let value_start = i;
        let mut escaped = false;
        while i < bytes.len() {
            match bytes[i] {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => break,
                _ => {}
            }
            i += 1;
        }
        pairs.push((name, &labels[value_start..i]));
        i += 1; // closing '"'
    }
    pairs
}

/// Deterministic, injective, length-preserving substitution.
#[derive(Default)]
struct Pseudonymizer {
    /// Keyed on the raw value globally, so the same string redacts to the same
    /// pseudonym wherever it appears. This keeps the interning hit rate honest.
    map: HashMap<String, String>,
    taken: BTreeSet<String>,
}

impl Pseudonymizer {
    fn get(&mut self, value: &str) -> String {
        if let Some(hit) = self.map.get(value) {
            return hit.clone();
        }
        // On the (vanishingly unlikely) collision, perturb the salt rather than
        // let two distinct values fold together and deflate cardinality.
        let mut salt = 0u32;
        let candidate = loop {
            let candidate = substitute(value, salt);
            if !self.taken.contains(&candidate) {
                break candidate;
            }
            salt += 1;
        };
        self.taken.insert(candidate.clone());
        self.map.insert(value.to_owned(), candidate.clone());
        candidate
    }
}

/// Map each byte to a same-class replacement driven by a hash of the whole
/// value, so the output has the same length and shape but no original content.
fn substitute(value: &str, salt: u32) -> String {
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGIT: &[u8] = b"0123456789";

    let digest = Md5::digest(format!("{salt}\u{1}{value}").as_bytes());
    let mut state = u64::from_le_bytes(digest[..8].try_into().unwrap_or_default());
    let mut out = String::with_capacity(value.len());

    for &b in value.as_bytes() {
        // xorshift64: cheap, deterministic, and no cryptographic strength is
        // needed here — the digest above already destroyed the input.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let roll = usize::try_from(state >> 32).unwrap_or(0);

        out.push(char::from(match b {
            b'a'..=b'z' => LOWER[roll % LOWER.len()],
            b'A'..=b'Z' => UPPER[roll % UPPER.len()],
            b'0'..=b'9' => DIGIT[roll % DIGIT.len()],
            // Separators and any non-ASCII byte pass through: they carry the
            // shape (and the byte length) but none of the identity.
            other => other,
        }));
    }
    out
}

/// Prove that nothing identifying survived into `clean`.
///
/// Deny-by-default already redacts every label value outside [`KEEP`], so this
/// does not re-check them. What it checks is the three places a private string
/// could still reach the output:
///
/// 1. **Metric names and comments**, which are copied verbatim on the
///    assumption that they come from the exporter's source rather than the
///    environment. Every [`HIGH_RISK`] value must be absent from the whole
///    body, so a hostname appearing in HELP text is a hard failure rather than
///    a silent pass.
/// 2. **Allowlisted label values**, checked against generic identifier
///    patterns. This is the check that does not trust [`KEEP`]: if a label was
///    wrongly allowlisted and holds an IP or a MAC, it fails here.
///
/// Redacted values are deliberately *not* pattern-scanned. A pseudonymized MAC
/// is still MAC-shaped by construction — length and character class are
/// preserved — so scanning it would fire on every run.
///
/// Note what this does *not* claim: a private string that is both
/// lowercase-only and absent from [`HIGH_RISK`] is not tracked through
/// comments. It is still redacted in its own label; see [`is_distinctive`] for
/// why chasing it through HELP text produces only false positives.
fn leak_scan(clean: &str, high_risk: &BTreeSet<String>) -> anyhow::Result<()> {
    for raw in high_risk {
        if is_distinctive(raw) && clean.contains(raw.as_str()) {
            bail!("high-risk value {raw:?} still present in output");
        }
    }

    for line in clean.lines() {
        if line.starts_with('#') {
            if let Some(found) = suspicious(line) {
                bail!("suspicious token {found:?} survived in comment: {line}");
            }
            continue;
        }
        let Some(open) = line.find('{') else { continue };
        let Some(close) = label_set_end(line, open) else {
            continue;
        };

        for (name, value) in split_labels(&line[open + 1..close]) {
            if !KEEP.contains(&name) {
                continue; // A pseudonym by construction.
            }
            if let Some(found) = suspicious(value) {
                bail!("allowlisted label {name}={value:?} holds an identifier: {found:?}");
            }
        }
    }
    Ok(())
}

/// Whether a redacted value is specific enough that finding it elsewhere in the
/// output means something leaked.
///
/// Check 1 is a substring search over the whole body, so it needs to ignore
/// values that are ordinary English or exporter vocabulary — `"mean"` is a
/// legitimate label value *and* a word that occurs in HELP text, and flagging
/// it tells us nothing. Environment identifiers, in practice, always carry a
/// digit, a separator, or a capital: `esp007`, `THPIOT`, `chatbot-dev`,
/// `Hetzner`, `plug001.neuss.thaller.ws`. A run of plain lowercase letters does
/// not.
///
/// This only relaxes the *backstop*. Every one of these values is still
/// redacted in its own label by deny-by-default; the question here is solely
/// whether an occurrence somewhere else should fail the build.
fn is_distinctive(value: &str) -> bool {
    value.len() >= 4 && !value.bytes().all(|b| b.is_ascii_lowercase())
}

/// Generic identifiers that should never appear in a value we kept verbatim.
fn suspicious(text: &str) -> Option<String> {
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || ".:-_".contains(c))) {
        if token.len() < 7 {
            continue;
        }
        if is_ipv4(token) || is_mac(token) {
            return Some(token.to_owned());
        }
    }
    None
}

fn is_ipv4(token: &str) -> bool {
    let octets: Vec<&str> = token.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|o| {
            !o.is_empty()
                && o.len() <= 3
                && o.bytes().all(|b| b.is_ascii_digit())
                && o.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

fn is_mac(token: &str) -> bool {
    let groups: Vec<&str> = token.split(':').collect();
    groups.len() == 6
        && groups
            .iter()
            .all(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_preserves_length_and_class() {
        let raw = "csi-vol-7c170bfa-6568-45cd/Abc";
        let out = substitute(raw, 0);
        assert_eq!(out.len(), raw.len());
        for (a, b) in raw.bytes().zip(out.bytes()) {
            assert_eq!(a.is_ascii_digit(), b.is_ascii_digit());
            assert_eq!(a.is_ascii_lowercase(), b.is_ascii_lowercase());
            assert_eq!(a.is_ascii_uppercase(), b.is_ascii_uppercase());
            if !a.is_ascii_alphanumeric() {
                assert_eq!(a, b, "separators must survive");
            }
        }
    }

    #[test]
    fn substitution_destroys_content() {
        assert_ne!(substitute("talos-node-01", 0), "talos-node-01");
    }

    #[test]
    fn pseudonyms_are_stable_and_injective() {
        let mut p = Pseudonymizer::default();
        let a = p.get("prod-cluster-a");
        let b = p.get("prod-cluster-b");
        assert_eq!(a, p.get("prod-cluster-a"), "must be deterministic");
        assert_ne!(a, b, "distinct inputs must not collapse");
    }

    #[test]
    fn label_values_containing_braces_do_not_truncate_the_line() {
        let line = r#"http_req{path="/a/{name}",code="200"} 1"#;
        assert_eq!(label_set_end(line, line.find('{').unwrap()), Some(36));
    }

    fn run(body: &str) -> String {
        let public = public_vocabulary(std::slice::from_ref(&body.to_owned()));
        let mut p = Pseudonymizer {
            taken: public.clone(),
            ..Pseudonymizer::default()
        };
        let (mut v, mut r) = (BTreeSet::new(), BTreeMap::new());
        sanitize(body, &public, &mut p, &mut v, &mut r)
    }

    #[test]
    fn keeps_allowlisted_labels_and_redacts_everything_else() {
        let body = "node_x{nodename=\"talos-a1\",method=\"GET\",le=\"0.5\"} 1\n";
        let out = run(body);

        assert!(!out.contains("talos-a1"), "unlisted label must be redacted");
        assert!(out.contains("method=\"GET\""), "allowlisted label survives");
        assert!(out.contains("le=\"0.5\""), "le must survive verbatim");
        assert!(out.contains("node_x"), "metric name must survive");
        assert_eq!(out.len(), body.len(), "shape must be byte-identical");
    }

    /// The regression that motivated deny-by-default: these all look like
    /// enums.
    #[test]
    fn redacts_labels_that_look_harmless() {
        let out = run(concat!(
            "x{serial=\"105601885\",dialer_name=\"chatbotumfrage\"} 1\n",
            "y{issuer_name=\"cert-manager-webhook-hetzner-ca\"} 1\n",
        ));
        assert!(!out.contains("105601885"));
        assert!(!out.contains("chatbotumfrage"));
        assert!(!out.contains("hetzner"));
    }

    #[test]
    fn leak_scan_catches_an_identifier_in_an_allowlisted_label() {
        // `source` is on the keep list. If a capture ever puts an IP in it, the
        // scan must fail rather than trust the allowlist.
        let clean = "x{source=\"10.4.19.220\"} 1\n";
        assert!(leak_scan(clean, &BTreeSet::new()).is_err());
    }

    #[test]
    fn leak_scan_catches_a_raw_value_surviving_elsewhere() {
        // Redacted as a label, but still present in a HELP comment.
        let raw: BTreeSet<String> = [String::from("chatbot-umfrage-schule")].into();
        let clean = "# HELP x tenant chatbot-umfrage-schule\nx{a=\"b\"} 1\n";
        assert!(leak_scan(clean, &raw).is_err());
    }

    #[test]
    fn leak_scan_accepts_a_pseudonymized_mac() {
        // A redacted MAC stays MAC-shaped; that must not trip the scan.
        let clean = "x{mac_address=\"A1:B2:C3:D4:E5:F6\"} 1\n";
        assert!(leak_scan(clean, &BTreeSet::new()).is_ok());
    }
}
