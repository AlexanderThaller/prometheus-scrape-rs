//! Kubernetes service discovery (`kubernetes_sd_configs`).
//!
//! Watches the API server with kube-rs reflectors and rebuilds target
//! groups (debounced) whenever a watched object changes. Supported roles:
//! `pod` and `endpointslice` — the two prometheus-operator generates for
//! podMonitors and serviceMonitors.
//!
//! Client configuration comes from the environment (in-cluster service
//! account or `KUBECONFIG`); one client is shared by all discoverers.

pub mod targets;

use std::{
    collections::HashMap,
    fmt::Debug,
    sync::Arc,
    time::Duration,
};

use futures::StreamExt as _;
use k8s_openapi::api::{
    core::v1::{
        Node,
        Pod,
        Service,
    },
    discovery::v1::EndpointSlice,
};
use kube::{
    api::Api,
    runtime::{
        WatchStreamExt as _,
        reflector::{
            self,
            Store,
        },
        watcher,
    },
};
use serde::de::DeserializeOwned;
use tokio::{
    sync::mpsc,
    task::JoinHandle,
};
use tracing::{
    debug,
    info,
    warn,
};

use crate::{
    config::{
        KubernetesRole,
        KubernetesSdConfig,
    },
    sd::TargetGroup,
};

/// Quiet period after a watch event before target groups are rebuilt, so
/// bursts (initial sync, rollouts) collapse into one update.
const DEBOUNCE: Duration = Duration::from_millis(500);

const SERVICE_ACCOUNT_NAMESPACE_FILE: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

static CLIENT: tokio::sync::OnceCell<kube::Client> = tokio::sync::OnceCell::const_new();

async fn shared_client() -> Result<kube::Client, kube::Error> {
    CLIENT
        .get_or_try_init(|| async {
            let client = kube::Client::try_default().await?;
            info!(cluster = %client.default_namespace(), "kubernetes client initialized");
            Ok(client)
        })
        .await
        .cloned()
}

/// Run discovery for one `kubernetes_sd_configs` entry, publishing complete
/// target-group sets as `(slot, groups)` updates.
pub async fn run(
    job: String,
    config: KubernetesSdConfig,
    slot: usize,
    update: mpsc::Sender<(usize, Vec<TargetGroup>)>,
) {
    let client = match shared_client().await {
        Ok(client) => client,
        Err(err) => {
            warn!(job, %err, "kubernetes client unavailable; kubernetes_sd disabled for this job");
            return;
        }
    };
    let namespaces = match namespaces(&config) {
        Ok(namespaces) => namespaces,
        Err(err) => {
            warn!(job, %err, "cannot resolve namespaces; kubernetes_sd disabled for this job");
            return;
        }
    };

    let (notify_tx, mut notify_rx) = mpsc::channel::<()>(64);
    let mut watch_tasks: Vec<JoinHandle<()>> = Vec::new();

    let mut pod_stores: Vec<Store<Pod>> = Vec::new();
    let mut slice_stores: Vec<Store<EndpointSlice>> = Vec::new();
    let mut service_stores: Vec<Store<Service>> = Vec::new();
    for namespace in &namespaces {
        let (store, task) = watch_resource(
            scoped_api::<Pod>(&client, namespace.as_deref()),
            &job,
            &notify_tx,
        );
        pod_stores.push(store);
        watch_tasks.push(task);
        if config.role == KubernetesRole::Endpointslice {
            let (store, task) = watch_resource(
                scoped_api::<EndpointSlice>(&client, namespace.as_deref()),
                &job,
                &notify_tx,
            );
            slice_stores.push(store);
            watch_tasks.push(task);
            let (store, task) = watch_resource(
                scoped_api::<Service>(&client, namespace.as_deref()),
                &job,
                &notify_tx,
            );
            service_stores.push(store);
            watch_tasks.push(task);
        }
    }
    let node_store: Option<Store<Node>> = if config.attach_metadata.node {
        let (store, task) = watch_resource(Api::<Node>::all(client.clone()), &job, &notify_tx);
        watch_tasks.push(task);
        Some(store)
    } else {
        None
    };
    drop(notify_tx);

    for store in &pod_stores {
        store.wait_until_ready().await.ok();
    }
    for store in &slice_stores {
        store.wait_until_ready().await.ok();
    }
    for store in &service_stores {
        store.wait_until_ready().await.ok();
    }
    if let Some(store) = &node_store {
        store.wait_until_ready().await.ok();
    }
    info!(job, role = ?config.role, namespaces = namespaces.len(), "kubernetes_sd synced");

    loop {
        let groups = build(
            config.role,
            &pod_stores,
            &slice_stores,
            &service_stores,
            node_store.as_ref(),
        );
        debug!(job, groups = groups.len(), "kubernetes_sd targets rebuilt");
        if update.send((slot, groups)).await.is_err() {
            break; // merger is gone; shutting down
        }

        // Wait for a change, then absorb the burst.
        if notify_rx.recv().await.is_none() {
            break;
        }
        while let Ok(Some(())) = tokio::time::timeout(DEBOUNCE, notify_rx.recv()).await {}
    }
    for task in watch_tasks {
        task.abort();
    }
}

fn build(
    role: KubernetesRole,
    pod_stores: &[Store<Pod>],
    slice_stores: &[Store<EndpointSlice>],
    service_stores: &[Store<Service>],
    node_store: Option<&Store<Node>>,
) -> Vec<TargetGroup> {
    let nodes: Option<HashMap<String, Arc<Node>>> = node_store.map(|store| {
        store
            .state()
            .into_iter()
            .filter_map(|node| Some((node.metadata.name.clone()?, node)))
            .collect()
    });
    let pods: Vec<Arc<Pod>> = pod_stores.iter().flat_map(Store::state).collect();
    match role {
        KubernetesRole::Pod => targets::pod_target_groups(&pods, nodes.as_ref()),
        KubernetesRole::Endpointslice => {
            let slices: Vec<Arc<EndpointSlice>> =
                slice_stores.iter().flat_map(Store::state).collect();
            let services: HashMap<(String, String), Arc<Service>> = service_stores
                .iter()
                .flat_map(Store::state)
                .filter_map(|service| {
                    let key = (
                        service.metadata.namespace.clone()?,
                        service.metadata.name.clone()?,
                    );
                    Some((key, service))
                })
                .collect();
            let pods_by_name: HashMap<(String, String), Arc<Pod>> = pods
                .into_iter()
                .filter_map(|pod| {
                    let key = (pod.metadata.namespace.clone()?, pod.metadata.name.clone()?);
                    Some((key, pod))
                })
                .collect();
            targets::endpointslice_target_groups(&slices, &services, &pods_by_name, nodes.as_ref())
        }
        // Rejected at config validation.
        _ => Vec::new(),
    }
}

/// Resolve the namespaces to watch; `None` means all namespaces.
fn namespaces(config: &KubernetesSdConfig) -> anyhow::Result<Vec<Option<String>>> {
    let mut names: Vec<Option<String>> =
        config.namespaces.names.iter().cloned().map(Some).collect();
    if config.namespaces.own_namespace {
        let own = std::fs::read_to_string(SERVICE_ACCOUNT_NAMESPACE_FILE)
            .map_err(|err| anyhow::anyhow!("reading {SERVICE_ACCOUNT_NAMESPACE_FILE}: {err}"))?;
        names.push(Some(own.trim().to_owned()));
    }
    if names.is_empty() {
        names.push(None);
    }
    names.dedup();
    Ok(names)
}

/// Build an `Api` for a namespace-scoped resource; `None` means all
/// namespaces.
fn scoped_api<K>(client: &kube::Client, namespace: Option<&str>) -> Api<K>
where
    K: kube::Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>,
{
    match namespace {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    }
}

/// Start a reflector for one resource kind. Watch errors (RBAC,
/// connectivity) are logged and retried with a fixed pause.
fn watch_resource<K>(
    api: Api<K>,
    job: &str,
    notify: &mpsc::Sender<()>,
) -> (Store<K>, JoinHandle<()>)
where
    K: kube::Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
{
    let kind = K::kind(&()).to_string();
    let job = job.to_owned();
    let notify = notify.clone();
    let (store, writer) = reflector::store();
    // managedFields is typically the largest part of a watched object and
    // nothing downstream reads it; dropping it before the reflector keeps
    // it out of the long-lived stores.
    let stream = reflector::reflector(
        writer,
        watcher(api, watcher::Config::default()).modify(|obj| {
            obj.meta_mut().managed_fields = None;
        }),
    );
    let task = tokio::spawn(async move {
        let mut stream = std::pin::pin!(stream);
        while let Some(event) = stream.next().await {
            match event {
                Ok(_) => {
                    let _ = notify.try_send(());
                }
                Err(err) => {
                    warn!(job, kind, %err, "kubernetes watch error; retrying");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
    (store, task)
}
