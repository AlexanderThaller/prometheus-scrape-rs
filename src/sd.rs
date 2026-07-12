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
/// The receiver always holds the current full set of target groups: static
/// groups first, then one slot per dynamic source (`file_sd`, one per
/// `kubernetes_sd_configs` entry). Each source pushes complete snapshots to
/// a merger task which publishes only on change.
#[must_use]
pub fn watch(config: &ScrapeConfig) -> (watch::Receiver<Vec<TargetGroup>>, Vec<JoinHandle<()>>) {
    let static_groups: Vec<TargetGroup> = config
        .static_configs
        .iter()
        .map(|sc| TargetGroup {
            targets: sc.targets.clone(),
            labels: sc.labels.clone(),
        })
        .collect();

    let has_files = !config.file_sd_configs.is_empty();
    let kubernetes_count = config.kubernetes_sd_configs.len();
    if !has_files && kubernetes_count == 0 {
        let (_tx, rx) = watch::channel(static_groups);
        return (rx, Vec::new());
    }

    let job = config.job_name.clone();
    let slot_count = usize::from(has_files) + kubernetes_count;
    let (update_tx, mut update_rx) =
        tokio::sync::mpsc::channel::<(usize, Vec<TargetGroup>)>(slot_count.max(1) * 2);
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    let mut slot = 0;

    if has_files {
        let file_sd_configs = config.file_sd_configs.clone();
        let job = job.clone();
        let update = update_tx.clone();
        let file_slot = slot;
        slot += 1;
        tasks.push(tokio::spawn(async move {
            let refresh = file_sd_configs
                .iter()
                .map(|c| c.refresh_interval.as_duration())
                .min()
                .unwrap_or(std::time::Duration::from_mins(5));
            let mut ticker = tokio::time::interval(refresh);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                let groups = read_file_sd(&file_sd_configs, &job);
                if update.send((file_slot, groups)).await.is_err() {
                    return;
                }
            }
        }));
    }
    for kubernetes_sd in &config.kubernetes_sd_configs {
        tasks.push(tokio::spawn(crate::sd_k8s::run(
            job.clone(),
            kubernetes_sd.clone(),
            slot,
            update_tx.clone(),
        )));
        slot += 1;
    }
    drop(update_tx);

    let (tx, rx) = watch::channel(static_groups.clone());
    tasks.push(tokio::spawn(async move {
        let mut slots: Vec<Vec<TargetGroup>> = vec![Vec::new(); slot_count];
        while let Some((index, groups)) = update_rx.recv().await {
            slots[index] = groups;
            let mut merged = static_groups.clone();
            for source in &slots {
                merged.extend(source.iter().cloned());
            }
            tx.send_if_modified(|current| {
                if *current == merged {
                    false
                } else {
                    debug!(job, groups = merged.len(), "discovered targets changed");
                    *current = merged;
                    true
                }
            });
        }
    }));
    (rx, tasks)
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
