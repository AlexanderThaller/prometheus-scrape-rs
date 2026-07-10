//! Target discovery: `static_configs` and `file_sd_configs`.

use std::collections::BTreeMap;

use serde::Deserialize;
use tokio::{
    sync::watch,
    task::JoinHandle,
};
use tracing::{
    debug,
    warn,
};

use crate::config::ScrapeConfig;

/// A group of targets sharing a label set, as produced by discovery.
///
/// This is also the on-disk format of `file_sd` files (a list of groups,
/// JSON or YAML — JSON parses as YAML).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TargetGroup {
    pub targets: Vec<String>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Start discovery for one scrape config.
///
/// The receiver always holds the current full set of target groups (static
/// groups first, then `file_sd` groups). A refresher task is spawned only when
/// `file_sd_configs` is present; it re-reads the files every
/// `refresh_interval` and publishes only on change.
#[must_use]
pub fn watch(config: &ScrapeConfig) -> (watch::Receiver<Vec<TargetGroup>>, Option<JoinHandle<()>>) {
    let static_groups: Vec<TargetGroup> = config
        .static_configs
        .iter()
        .map(|sc| TargetGroup {
            targets: sc.targets.clone(),
            labels: sc.labels.clone(),
        })
        .collect();

    if config.file_sd_configs.is_empty() {
        let (_tx, rx) = watch::channel(static_groups);
        return (rx, None);
    }

    let file_sd_configs = config.file_sd_configs.clone();
    let job = config.job_name.clone();
    let mut initial = static_groups.clone();
    initial.extend(read_file_sd(&file_sd_configs, &job));
    let (tx, rx) = watch::channel(initial);

    let refresh = file_sd_configs
        .iter()
        .map(|c| c.refresh_interval.as_duration())
        .min()
        .unwrap_or(std::time::Duration::from_secs(300));

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(refresh);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await; // first tick fires immediately; initial state is already set
        loop {
            ticker.tick().await;
            let mut groups = static_groups.clone();
            groups.extend(read_file_sd(&file_sd_configs, &job));
            tx.send_if_modified(|current| {
                if *current == groups {
                    false
                } else {
                    debug!(job, groups = groups.len(), "file_sd targets changed");
                    *current = groups;
                    true
                }
            });
        }
    });
    (rx, Some(handle))
}

/// Read and parse all `file_sd` files. Unreadable or malformed files are
/// skipped with a warning, matching Prometheus (a bad file must not take
/// down targets discovered from other files).
fn read_file_sd(configs: &[crate::config::FileSdConfig], job: &str) -> Vec<TargetGroup> {
    let mut groups = Vec::new();
    for config in configs {
        for pattern in &config.files {
            let paths = match glob::glob(pattern) {
                Ok(paths) => paths,
                Err(err) => {
                    warn!(job, pattern, %err, "invalid file_sd glob pattern");
                    continue;
                }
            };
            for path in paths {
                let path = match path {
                    Ok(path) => path,
                    Err(err) => {
                        warn!(job, pattern, %err, "file_sd glob error");
                        continue;
                    }
                };
                let contents = match std::fs::read_to_string(&path) {
                    Ok(contents) => contents,
                    Err(err) => {
                        warn!(job, path = %path.display(), %err, "reading file_sd file");
                        continue;
                    }
                };
                match serde_saphyr::from_str::<Vec<TargetGroup>>(&contents) {
                    Ok(parsed) => groups.extend(parsed),
                    Err(err) => {
                        warn!(job, path = %path.display(), %err, "parsing file_sd file");
                    }
                }
            }
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_group_parses_json_and_yaml() -> anyhow::Result<()> {
        let json = r#"[{"targets": ["a:9100", "b:9100"], "labels": {"env": "prod"}}]"#;
        let yaml = "- targets: ['a:9100', 'b:9100']\n  labels:\n    env: prod\n";
        let from_json: Vec<TargetGroup> = serde_saphyr::from_str(json)?;
        let from_yaml: Vec<TargetGroup> = serde_saphyr::from_str(yaml)?;
        assert_eq!(from_json, from_yaml);
        assert_eq!(from_json[0].targets.len(), 2);
        assert_eq!(from_json[0].labels["env"], "prod");
        Ok(())
    }
}
