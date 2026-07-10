//! Target-group builders: Kubernetes objects in, Prometheus target groups
//! with `__meta_kubernetes_*` labels out.
//!
//! These are direct ports of Prometheus' `discovery/kubernetes` package —
//! `pod.go` (`buildPod`/`podLabels`) and `endpointslice.go`
//! (`buildEndpointSlice`) — with the shared helpers `addObjectMetaLabels`,
//! `addNodeLabels` and `serviceLabels` from `kubernetes.go`/`endpoints.go`.
//! Label names and construction logic are kept faithful to the Go source so
//! that relabel configs written against upstream Prometheus behave
//! identically.
//!
//! Our pipeline merges a group's labels into each of its targets, so per
//! target label sets are expressed as one [`TargetGroup`] per target with a
//! single-element `targets` vector.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use k8s_openapi::api::core::v1::Container;
use k8s_openapi::api::core::v1::Node;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::Endpoint;
use k8s_openapi::api::discovery::v1::EndpointPort;
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use crate::sd::TargetGroup;

/// Common prefix for every discovery meta label (`model.MetaLabelPrefix +
/// "kubernetes_"` in the Go source).
const META_PREFIX: &str = "__meta_kubernetes_";

/// Slice label set by the `EndpointSlice` controller that names the owning
/// service.
const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";

/// Port `SanitizeLabelName`: every character outside `[a-zA-Z0-9_]` becomes
/// `_`. Equivalent to Prometheus' `strutil.SanitizeLabelName`.
fn sanitize_label_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

/// Format `host:port`, bracketing IPv6 hosts, mirroring Go's
/// `net.JoinHostPort`.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Append `<role>_label_*` / `<role>_labelpresent_*` and the annotation
/// equivalents from an object's metadata. Port of
/// `addObjectAnnotationsAndLabels`.
fn add_object_annotations_and_labels(
    labels: &mut BTreeMap<String, String>,
    meta: &ObjectMeta,
    role: &str,
) {
    if let Some(object_labels) = &meta.labels {
        for (key, value) in object_labels {
            let sanitized = sanitize_label_name(key);
            labels.insert(format!("{META_PREFIX}{role}_label_{sanitized}"), value.clone());
            labels.insert(
                format!("{META_PREFIX}{role}_labelpresent_{sanitized}"),
                "true".to_owned(),
            );
        }
    }
    if let Some(annotations) = &meta.annotations {
        for (key, value) in annotations {
            let sanitized = sanitize_label_name(key);
            labels.insert(format!("{META_PREFIX}{role}_annotation_{sanitized}"), value.clone());
            labels.insert(
                format!("{META_PREFIX}{role}_annotationpresent_{sanitized}"),
                "true".to_owned(),
            );
        }
    }
}

/// Add `<role>_name` plus the label/annotation set. Port of
/// `addObjectMetaLabels`.
fn add_object_meta_labels(labels: &mut BTreeMap<String, String>, meta: &ObjectMeta, role: &str) {
    labels.insert(
        format!("{META_PREFIX}{role}_name"),
        meta.name.clone().unwrap_or_default(),
    );
    add_object_annotations_and_labels(labels, meta, role);
}

/// Merge the node's `RoleNode` object-meta labels into `labels`, if the node
/// is present in the store. Port of `addNodeLabels` (which only emits the
/// object-meta set for attach-metadata, not conditions/provider id).
fn add_node_labels(
    labels: &mut BTreeMap<String, String>,
    nodes: Option<&HashMap<String, Arc<Node>>>,
    node_name: Option<&str>,
) {
    let (Some(nodes), Some(node_name)) = (nodes, node_name) else {
        return;
    };
    if node_name.is_empty() {
        return;
    }
    if let Some(node) = nodes.get(node_name) {
        add_object_meta_labels(labels, &node.metadata, "node");
    }
}

/// `__meta_kubernetes_pod_ready`: lower-cased status of the `Ready`
/// condition, or `unknown` when absent. Port of `podReady`.
fn pod_ready(pod: &Pod) -> String {
    if let Some(status) = &pod.status
        && let Some(conditions) = &status.conditions
    {
        for cond in conditions {
            if cond.type_ == "Ready" {
                return cond.status.to_lowercase();
            }
        }
    }
    "unknown".to_owned()
}

/// The controlling owner reference (the one with `controller: true`), if any.
/// Port of `GetControllerOf`.
fn controller_of(
    meta: &ObjectMeta,
) -> Option<&k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference> {
    meta.owner_references
        .as_ref()?
        .iter()
        .find(|owner| owner.controller == Some(true))
}

/// Build the group-level pod label set. Port of `podLabels` (without the
/// deployment/job/cronjob metadata, which our config does not enable).
fn pod_labels(pod: &Pod) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    let status = pod.status.as_ref();

    labels.insert(
        format!("{META_PREFIX}pod_ip"),
        status.and_then(|s| s.pod_ip.clone()).unwrap_or_default(),
    );
    labels.insert(format!("{META_PREFIX}pod_ready"), pod_ready(pod));
    labels.insert(
        format!("{META_PREFIX}pod_phase"),
        status.and_then(|s| s.phase.clone()).unwrap_or_default(),
    );
    labels.insert(
        format!("{META_PREFIX}pod_node_name"),
        pod.spec.as_ref().and_then(|s| s.node_name.clone()).unwrap_or_default(),
    );
    labels.insert(
        format!("{META_PREFIX}pod_host_ip"),
        status.and_then(|s| s.host_ip.clone()).unwrap_or_default(),
    );
    labels.insert(
        format!("{META_PREFIX}pod_uid"),
        pod.metadata.uid.clone().unwrap_or_default(),
    );

    add_object_meta_labels(&mut labels, &pod.metadata, "pod");

    if let Some(owner) = controller_of(&pod.metadata) {
        if !owner.kind.is_empty() {
            labels.insert(format!("{META_PREFIX}pod_controller_kind"), owner.kind.clone());
        }
        if !owner.name.is_empty() {
            labels.insert(format!("{META_PREFIX}pod_controller_name"), owner.name.clone());
        }
    }

    labels
}

/// Container id from the matching status entry, empty when not found. Port of
/// `findPodContainerID`.
fn find_container_id(statuses: Option<&[k8s_openapi::api::core::v1::ContainerStatus]>, name: &str) -> String {
    statuses
        .into_iter()
        .flatten()
        .find(|status| status.name == name)
        .and_then(|status| status.container_id.clone())
        .unwrap_or_default()
}

/// Regular containers followed by init containers, paired with whether each
/// is an init container. Mirrors `append(pod.Spec.Containers,
/// pod.Spec.InitContainers...)` plus the `i >= len(Containers)` init check.
fn all_containers(pod: &Pod) -> Vec<(&Container, bool)> {
    let spec = pod.spec.as_ref();
    let regular = spec.map(|s| s.containers.as_slice()).unwrap_or_default();
    let init = spec.and_then(|s| s.init_containers.as_deref()).unwrap_or_default();
    regular
        .iter()
        .map(|c| (c, false))
        .chain(init.iter().map(|c| (c, true)))
        .collect()
}

/// One target group per container/port of every pod with an IP. Port of
/// `buildPod`.
#[must_use]
#[expect(
    clippy::implicit_hasher,
    reason = "signature is fixed by the sd_k8s.rs caller, which passes the default hasher"
)]
pub fn pod_target_groups(
    pods: &[Arc<Pod>],
    nodes: Option<&HashMap<String, Arc<Node>>>,
) -> Vec<TargetGroup> {
    let mut groups = Vec::new();

    for pod in pods {
        let pod_ip = pod.status.as_ref().and_then(|s| s.pod_ip.as_deref()).unwrap_or("");
        // PodIP can be empty when a pod is starting or has been evicted.
        if pod_ip.is_empty() {
            continue;
        }

        let node_name = pod.spec.as_ref().and_then(|s| s.node_name.as_deref());
        // With attach_metadata=node, pods on nodes filtered out of the store
        // (by node selectors) are dropped entirely.
        if let Some(nodes) = nodes {
            match node_name {
                Some(name) if nodes.contains_key(name) => {}
                _ => continue,
            }
        }

        let mut base = pod_labels(pod);
        base.insert(
            format!("{META_PREFIX}namespace"),
            pod.metadata.namespace.clone().unwrap_or_default(),
        );
        add_node_labels(&mut base, nodes, node_name);

        let status = pod.status.as_ref();
        for (container, is_init) in all_containers(pod) {
            let statuses = if is_init {
                status.and_then(|s| s.init_container_statuses.as_deref())
            } else {
                status.and_then(|s| s.container_statuses.as_deref())
            };
            let container_id = find_container_id(statuses, &container.name);
            let image = container.image.clone().unwrap_or_default();

            let ports = container.ports.as_deref().unwrap_or_default();
            if ports.is_empty() {
                // No port: anonymous target at the pod IP, no port labels.
                let mut labels = base.clone();
                labels.insert(format!("{META_PREFIX}address"), pod_ip.to_owned());
                labels.insert(format!("{META_PREFIX}pod_container_name"), container.name.clone());
                labels.insert(format!("{META_PREFIX}pod_container_id"), container_id.clone());
                labels.insert(format!("{META_PREFIX}pod_container_image"), image.clone());
                labels.insert(format!("{META_PREFIX}pod_container_init"), is_init.to_string());
                groups.push(single_target(labels));
                continue;
            }

            for port in ports {
                let port_number = port.container_port.to_string();
                let addr = join_host_port(pod_ip, &port_number);

                let mut labels = base.clone();
                labels.insert(format!("{META_PREFIX}address"), addr);
                labels.insert(format!("{META_PREFIX}pod_container_name"), container.name.clone());
                labels.insert(format!("{META_PREFIX}pod_container_id"), container_id.clone());
                labels.insert(format!("{META_PREFIX}pod_container_image"), image.clone());
                labels.insert(format!("{META_PREFIX}pod_container_port_number"), port_number);
                labels.insert(
                    format!("{META_PREFIX}pod_container_port_name"),
                    port.name.clone().unwrap_or_default(),
                );
                labels.insert(
                    format!("{META_PREFIX}pod_container_port_protocol"),
                    port.protocol.clone().unwrap_or_default(),
                );
                labels.insert(format!("{META_PREFIX}pod_container_init"), is_init.to_string());
                groups.push(single_target(labels));
            }
        }
    }

    groups
}

/// Wrap a full label set as a single-target group, moving `__address__` out
/// of the label map into the `targets` vector.
fn single_target(mut labels: BTreeMap<String, String>) -> TargetGroup {
    let address = labels
        .remove(&format!("{META_PREFIX}address"))
        .unwrap_or_default();
    TargetGroup { targets: vec![address], labels }
}

/// One target group per endpoint/port pair of every slice, joined with the
/// owning service and the backing pods. Port of `buildEndpointSlice`.
#[must_use]
#[expect(
    clippy::implicit_hasher,
    reason = "signature is fixed by the sd_k8s.rs caller, which passes default hashers"
)]
pub fn endpointslice_target_groups(
    slices: &[Arc<EndpointSlice>],
    services: &HashMap<(String, String), Arc<Service>>,
    pods: &HashMap<(String, String), Arc<Pod>>,
    nodes: Option<&HashMap<String, Arc<Node>>>,
) -> Vec<TargetGroup> {
    let mut groups = Vec::new();

    for slice in slices {
        let namespace = slice.metadata.namespace.clone().unwrap_or_default();

        let mut slice_labels = BTreeMap::new();
        slice_labels.insert(format!("{META_PREFIX}namespace"), namespace.clone());
        slice_labels.insert(
            format!("{META_PREFIX}endpointslice_address_type"),
            slice.address_type.clone(),
        );
        add_object_meta_labels(&mut slice_labels, &slice.metadata, "endpointslice");

        // Owning service via the service-name slice label.
        if let Some(service_name) = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(SERVICE_NAME_LABEL))
            && let Some(service) = services.get(&(namespace.clone(), service_name.clone()))
        {
            slice_labels.insert(
                format!("{META_PREFIX}namespace"),
                service.metadata.namespace.clone().unwrap_or_default(),
            );
            add_object_meta_labels(&mut slice_labels, &service.metadata, "service");
        }

        // Tracks, per referenced pod, the container ports already emitted so
        // additional pod ports can be added afterwards.
        let mut seen_pods: HashMap<(String, String), Vec<i32>> = HashMap::new();

        let ports = slice.ports.as_deref().unwrap_or_default();
        for endpoint in slice.endpoints.as_deref().unwrap_or_default() {
            for port in ports {
                for addr in &endpoint.addresses {
                    let mut labels = slice_labels.clone();
                    build_endpoint_target(
                        &mut labels,
                        addr,
                        endpoint,
                        port,
                        pods,
                        nodes,
                        &mut seen_pods,
                    );
                    groups.push(single_target(labels));
                }
            }
        }

        // Additional targets for pod container ports the slice did not cover.
        for ((pod_ns, pod_name), service_ports) in &seen_pods {
            let Some(pod) = pods.get(&(pod_ns.clone(), pod_name.clone())) else {
                continue;
            };
            let pod_ip = pod.status.as_ref().and_then(|s| s.pod_ip.as_deref()).unwrap_or("");
            if pod_ip.is_empty() {
                continue;
            }

            let full_pod_labels = pod_labels(pod);
            for (container, is_init) in all_containers(pod) {
                for cport in container.ports.as_deref().unwrap_or_default() {
                    if service_ports.contains(&cport.container_port) {
                        continue;
                    }
                    let port_number = cport.container_port.to_string();
                    let addr = join_host_port(pod_ip, &port_number);

                    let mut labels = slice_labels.clone();
                    // Endpoint labels do not apply to these synthetic ports;
                    // only the pod/container/port set does.
                    for (key, value) in &full_pod_labels {
                        labels.insert(key.clone(), value.clone());
                    }
                    labels.insert(format!("{META_PREFIX}address"), addr);
                    labels.insert(format!("{META_PREFIX}pod_container_name"), container.name.clone());
                    labels.insert(
                        format!("{META_PREFIX}pod_container_image"),
                        container.image.clone().unwrap_or_default(),
                    );
                    labels.insert(
                        format!("{META_PREFIX}pod_container_port_name"),
                        cport.name.clone().unwrap_or_default(),
                    );
                    labels.insert(format!("{META_PREFIX}pod_container_port_number"), port_number);
                    labels.insert(
                        format!("{META_PREFIX}pod_container_port_protocol"),
                        cport.protocol.clone().unwrap_or_default(),
                    );
                    labels.insert(format!("{META_PREFIX}pod_container_init"), is_init.to_string());
                    groups.push(single_target(labels));
                }
            }
        }
    }

    groups
}

/// Fill in one endpoint/port target's endpoint, node and (for `Pod`
/// targetRefs) pod/container labels; records the port against the pod in
/// `seen_pods`. Port of the `add` closure in `buildEndpointSlice`.
#[expect(
    clippy::too_many_lines,
    reason = "faithful port of the Go `add` closure; splitting it would obscure the mapping"
)]
fn build_endpoint_target(
    labels: &mut BTreeMap<String, String>,
    addr: &str,
    endpoint: &Endpoint,
    port: &EndpointPort,
    pods: &HashMap<(String, String), Arc<Pod>>,
    nodes: Option<&HashMap<String, Arc<Node>>>,
    seen_pods: &mut HashMap<(String, String), Vec<i32>>,
) {
    let address = match port.port {
        Some(number) => join_host_port(addr, &number.to_string()),
        None => addr.to_owned(),
    };
    labels.insert(format!("{META_PREFIX}address"), address);

    if let Some(name) = &port.name {
        labels.insert(format!("{META_PREFIX}endpointslice_port_name"), name.clone());
    }
    if let Some(protocol) = &port.protocol {
        labels.insert(format!("{META_PREFIX}endpointslice_port_protocol"), protocol.clone());
    }
    if let Some(number) = port.port {
        labels.insert(format!("{META_PREFIX}endpointslice_port"), number.to_string());
    }
    if let Some(app_protocol) = &port.app_protocol {
        labels.insert(
            format!("{META_PREFIX}endpointslice_port_app_protocol"),
            app_protocol.clone(),
        );
    }

    if let Some(conditions) = &endpoint.conditions {
        if let Some(ready) = conditions.ready {
            labels.insert(
                format!("{META_PREFIX}endpointslice_endpoint_conditions_ready"),
                ready.to_string(),
            );
        }
        if let Some(serving) = conditions.serving {
            labels.insert(
                format!("{META_PREFIX}endpointslice_endpoint_conditions_serving"),
                serving.to_string(),
            );
        }
        if let Some(terminating) = conditions.terminating {
            labels.insert(
                format!("{META_PREFIX}endpointslice_endpoint_conditions_terminating"),
                terminating.to_string(),
            );
        }
    }

    if let Some(hostname) = &endpoint.hostname {
        labels.insert(format!("{META_PREFIX}endpointslice_endpoint_hostname"), hostname.clone());
    }

    if let Some(target_ref) = &endpoint.target_ref {
        labels.insert(
            format!("{META_PREFIX}endpointslice_address_target_kind"),
            target_ref.kind.clone().unwrap_or_default(),
        );
        labels.insert(
            format!("{META_PREFIX}endpointslice_address_target_name"),
            target_ref.name.clone().unwrap_or_default(),
        );
    }

    if let Some(node_name) = &endpoint.node_name {
        labels.insert(format!("{META_PREFIX}endpointslice_endpoint_node_name"), node_name.clone());
    }
    if let Some(zone) = &endpoint.zone {
        labels.insert(format!("{META_PREFIX}endpointslice_endpoint_zone"), zone.clone());
    }

    if let Some(topology) = &endpoint.deprecated_topology {
        for (key, value) in topology {
            let sanitized = sanitize_label_name(key);
            labels.insert(
                format!("{META_PREFIX}endpointslice_endpoint_topology_{sanitized}"),
                value.clone(),
            );
            labels.insert(
                format!("{META_PREFIX}endpointslice_endpoint_topology_present_{sanitized}"),
                "true".to_owned(),
            );
        }
    }

    // Node metadata: from the targetRef when it is a Node, otherwise from the
    // endpoint's node name.
    if nodes.is_some() {
        match &endpoint.target_ref {
            Some(target_ref) if target_ref.kind.as_deref() == Some("Node") => {
                add_node_labels(labels, nodes, target_ref.name.as_deref());
            }
            _ => add_node_labels(labels, nodes, endpoint.node_name.as_deref()),
        }
    }

    // Pod join: only for Pod targetRefs found in the store, keyed by
    // (namespace, name) as `resolvePodRef` does via `namespacedName`.
    let pod = endpoint.target_ref.as_ref().and_then(|target_ref| {
        if target_ref.kind.as_deref() != Some("Pod") {
            return None;
        }
        let ns = target_ref.namespace.clone()?;
        let name = target_ref.name.clone()?;
        pods.get(&(ns, name))
    });

    let Some(pod) = pod else {
        return;
    };
    let ns = pod.metadata.namespace.clone().unwrap_or_default();
    let name = pod.metadata.name.clone().unwrap_or_default();

    // Merge the full pod label set (target labels win on conflict, matching
    // `target.Merge(podLabels(...))` where the receiver takes precedence).
    for (key, value) in pod_labels(pod) {
        labels.entry(key).or_insert(value);
    }

    // Container/port labels: the container whose port matches this endpoint
    // port number.
    if let Some(port_number) = port.port {
        'outer: for (container, is_init) in all_containers(pod) {
            for cport in container.ports.as_deref().unwrap_or_default() {
                if cport.container_port == port_number {
                    labels.insert(format!("{META_PREFIX}pod_container_name"), container.name.clone());
                    labels.insert(
                        format!("{META_PREFIX}pod_container_image"),
                        container.image.clone().unwrap_or_default(),
                    );
                    labels.insert(
                        format!("{META_PREFIX}pod_container_port_name"),
                        cport.name.clone().unwrap_or_default(),
                    );
                    labels.insert(
                        format!("{META_PREFIX}pod_container_port_number"),
                        port_number.to_string(),
                    );
                    labels.insert(
                        format!("{META_PREFIX}pod_container_port_protocol"),
                        cport.protocol.clone().unwrap_or_default(),
                    );
                    labels.insert(format!("{META_PREFIX}pod_container_init"), is_init.to_string());
                    break 'outer;
                }
            }
        }
    }

    // Record the port so additional (uncovered) ports can be added later.
    seen_pods.entry((ns, name)).or_default().extend(port.port);
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::ContainerPort;
    use k8s_openapi::api::core::v1::ContainerStatus;
    use k8s_openapi::api::core::v1::PodCondition;
    use k8s_openapi::api::core::v1::PodSpec;
    use k8s_openapi::api::core::v1::PodStatus;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::api::discovery::v1::EndpointConditions;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
    use k8s_openapi::api::core::v1::ObjectReference;

    use super::*;

    fn container(name: &str, image: &str, ports: Vec<ContainerPort>) -> Container {
        Container {
            name: name.to_owned(),
            image: Some(image.to_owned()),
            ports: if ports.is_empty() { None } else { Some(ports) },
            ..Default::default()
        }
    }

    fn port(name: &str, number: i32, protocol: &str) -> ContainerPort {
        ContainerPort {
            name: Some(name.to_owned()),
            container_port: number,
            protocol: Some(protocol.to_owned()),
            ..Default::default()
        }
    }

    fn labels_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
    }

    /// Pod: 2 labels (one dotted key), 1 annotation, a controller owner ref,
    /// ready condition, a regular container with two ports, a portless
    /// container, and an init container with a port.
    fn sample_pod() -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some("web-0".to_owned()),
                namespace: Some("default".to_owned()),
                uid: Some("uid-123".to_owned()),
                labels: Some(labels_map(&[
                    ("app.kubernetes.io/name", "web"),
                    ("tier", "frontend"),
                ])),
                annotations: Some(labels_map(&[("prometheus.io/scrape", "true")])),
                owner_references: Some(vec![OwnerReference {
                    kind: "ReplicaSet".to_owned(),
                    name: "web".to_owned(),
                    controller: Some(true),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            spec: Some(PodSpec {
                node_name: Some("node-a".to_owned()),
                containers: vec![
                    container(
                        "app",
                        "app:1",
                        vec![port("http", 8080, "TCP"), port("metrics", 9090, "TCP")],
                    ),
                    container("sidecar", "side:1", vec![]),
                ],
                init_containers: Some(vec![container("init", "init:1", vec![port("boot", 7000, "TCP")])]),
                ..Default::default()
            }),
            status: Some(PodStatus {
                pod_ip: Some("10.0.0.5".to_owned()),
                host_ip: Some("192.168.1.1".to_owned()),
                phase: Some("Running".to_owned()),
                conditions: Some(vec![PodCondition {
                    type_: "Ready".to_owned(),
                    status: "True".to_owned(),
                    ..Default::default()
                }]),
                container_statuses: Some(vec![ContainerStatus {
                    name: "app".to_owned(),
                    container_id: Some("containerd://abc".to_owned()),
                    image: "app:1".to_owned(),
                    image_id: String::new(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
        }
    }

    fn find<'a>(groups: &'a [TargetGroup], address: &str) -> &'a TargetGroup {
        groups
            .iter()
            .find(|g| g.targets == [address.to_owned()])
            .unwrap_or_else(|| panic!("no target group for {address}"))
    }

    #[test]
    fn pod_group_and_container_labels() {
        let pod = Arc::new(sample_pod());
        let groups = pod_target_groups(&[pod], None);

        // 2 ports on app + 1 portless sidecar + 1 init port = 4 targets.
        assert_eq!(groups.len(), 4);

        let http = find(&groups, "10.0.0.5:8080");
        let l = &http.labels;
        assert_eq!(l[&format!("{META_PREFIX}namespace")], "default");
        assert_eq!(l[&format!("{META_PREFIX}pod_name")], "web-0");
        assert_eq!(l[&format!("{META_PREFIX}pod_ip")], "10.0.0.5");
        assert_eq!(l[&format!("{META_PREFIX}pod_ready")], "true");
        assert_eq!(l[&format!("{META_PREFIX}pod_phase")], "Running");
        assert_eq!(l[&format!("{META_PREFIX}pod_node_name")], "node-a");
        assert_eq!(l[&format!("{META_PREFIX}pod_host_ip")], "192.168.1.1");
        assert_eq!(l[&format!("{META_PREFIX}pod_uid")], "uid-123");
        assert_eq!(l[&format!("{META_PREFIX}pod_controller_kind")], "ReplicaSet");
        assert_eq!(l[&format!("{META_PREFIX}pod_controller_name")], "web");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_name")], "app");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_id")], "containerd://abc");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_image")], "app:1");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_port_name")], "http");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_port_number")], "8080");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_port_protocol")], "TCP");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_init")], "false");
    }

    #[test]
    fn dotted_label_keys_are_sanitized() {
        let pod = Arc::new(sample_pod());
        let groups = pod_target_groups(&[pod], None);
        let l = &find(&groups, "10.0.0.5:8080").labels;
        assert_eq!(l[&format!("{META_PREFIX}pod_label_app_kubernetes_io_name")], "web");
        assert_eq!(l[&format!("{META_PREFIX}pod_labelpresent_app_kubernetes_io_name")], "true");
        assert_eq!(l[&format!("{META_PREFIX}pod_label_tier")], "frontend");
        assert_eq!(l[&format!("{META_PREFIX}pod_annotation_prometheus_io_scrape")], "true");
        assert_eq!(
            l[&format!("{META_PREFIX}pod_annotationpresent_prometheus_io_scrape")],
            "true"
        );
    }

    #[test]
    fn portless_container_uses_pod_ip_without_port() {
        let pod = Arc::new(sample_pod());
        let groups = pod_target_groups(&[pod], None);
        let g = find(&groups, "10.0.0.5");
        assert_eq!(g.labels[&format!("{META_PREFIX}pod_container_name")], "sidecar");
        // No port labels for a portless container.
        assert!(!g.labels.contains_key(&format!("{META_PREFIX}pod_container_port_number")));
    }

    #[test]
    fn init_container_flagged_and_addressed() {
        let pod = Arc::new(sample_pod());
        let groups = pod_target_groups(&[pod], None);
        let g = find(&groups, "10.0.0.5:7000");
        assert_eq!(g.labels[&format!("{META_PREFIX}pod_container_name")], "init");
        assert_eq!(g.labels[&format!("{META_PREFIX}pod_container_init")], "true");
        // Init container has no status entry, so container id is empty.
        assert_eq!(g.labels[&format!("{META_PREFIX}pod_container_id")], "");
    }

    #[test]
    fn pods_without_ip_are_skipped() {
        let mut pod = sample_pod();
        pod.status.as_mut().unwrap().pod_ip = None;
        let groups = pod_target_groups(&[Arc::new(pod)], None);
        assert!(groups.is_empty());
    }

    #[test]
    fn ipv6_pod_ip_is_bracketed() {
        let mut pod = sample_pod();
        pod.status.as_mut().unwrap().pod_ip = Some("fd00::1".to_owned());
        let groups = pod_target_groups(&[Arc::new(pod)], None);
        assert!(groups.iter().any(|g| g.targets == ["[fd00::1]:8080".to_owned()]));
    }

    #[test]
    fn node_metadata_attached_and_filters_missing_nodes() {
        let pod = Arc::new(sample_pod());
        let node = Arc::new(Node {
            metadata: ObjectMeta {
                name: Some("node-a".to_owned()),
                labels: Some(labels_map(&[("topology.kubernetes.io/zone", "eu-1")])),
                ..Default::default()
            },
            ..Default::default()
        });
        let nodes: HashMap<String, Arc<Node>> = [("node-a".to_owned(), node)].into_iter().collect();

        let groups = pod_target_groups(std::slice::from_ref(&pod), Some(&nodes));
        let l = &find(&groups, "10.0.0.5:8080").labels;
        assert_eq!(l[&format!("{META_PREFIX}node_name")], "node-a");
        assert_eq!(l[&format!("{META_PREFIX}node_label_topology_kubernetes_io_zone")], "eu-1");

        // A pod on a node absent from the store is dropped entirely.
        let empty: HashMap<String, Arc<Node>> = HashMap::new();
        assert!(pod_target_groups(&[pod], Some(&empty)).is_empty());
    }

    fn endpoint_port(name: &str, number: i32) -> EndpointPort {
        EndpointPort {
            name: Some(name.to_owned()),
            port: Some(number),
            protocol: Some("TCP".to_owned()),
            ..Default::default()
        }
    }

    fn sample_service() -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some("web".to_owned()),
                namespace: Some("default".to_owned()),
                labels: Some(labels_map(&[("team", "core")])),
                ..Default::default()
            },
            spec: Some(ServiceSpec::default()),
            ..Default::default()
        }
    }

    fn sample_slice() -> EndpointSlice {
        EndpointSlice {
            metadata: ObjectMeta {
                name: Some("web-abcde".to_owned()),
                namespace: Some("default".to_owned()),
                labels: Some(labels_map(&[(SERVICE_NAME_LABEL, "web")])),
                ..Default::default()
            },
            address_type: "IPv4".to_owned(),
            endpoints: Some(vec![
                Endpoint {
                    addresses: vec!["10.0.0.5".to_owned()],
                    conditions: Some(EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: None,
                    }),
                    hostname: Some("web-0".to_owned()),
                    node_name: Some("node-a".to_owned()),
                    zone: Some("eu-1".to_owned()),
                    target_ref: Some(ObjectReference {
                        kind: Some("Pod".to_owned()),
                        name: Some("web-0".to_owned()),
                        namespace: Some("default".to_owned()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Endpoint {
                    addresses: vec!["10.0.0.6".to_owned()],
                    conditions: Some(EndpointConditions {
                        ready: Some(false),
                        serving: None,
                        terminating: None,
                    }),
                    ..Default::default()
                },
            ]),
            ports: Some(vec![endpoint_port("http", 8080)]),
        }
    }

    type ServiceMap = HashMap<(String, String), Arc<Service>>;
    type PodMap = HashMap<(String, String), Arc<Pod>>;

    fn slice_inputs() -> (ServiceMap, PodMap) {
        let services = [(("default".to_owned(), "web".to_owned()), Arc::new(sample_service()))]
            .into_iter()
            .collect();
        let pods = [(("default".to_owned(), "web-0".to_owned()), Arc::new(sample_pod()))]
            .into_iter()
            .collect();
        (services, pods)
    }

    #[test]
    fn endpointslice_core_labels() {
        let (services, pods) = slice_inputs();
        let groups = endpointslice_target_groups(&[Arc::new(sample_slice())], &services, &pods, None);

        let g = find(&groups, "10.0.0.5:8080");
        let l = &g.labels;
        assert_eq!(l[&format!("{META_PREFIX}namespace")], "default");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_name")], "web-abcde");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_address_type")], "IPv4");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_port_name")], "http");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_port")], "8080");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_port_protocol")], "TCP");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_endpoint_conditions_ready")], "true");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_endpoint_conditions_serving")], "true");
        // Terminating condition was nil, so its label is absent.
        assert!(!l.contains_key(&format!("{META_PREFIX}endpointslice_endpoint_conditions_terminating")));
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_endpoint_hostname")], "web-0");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_endpoint_node_name")], "node-a");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_endpoint_zone")], "eu-1");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_address_target_kind")], "Pod");
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_address_target_name")], "web-0");
    }

    #[test]
    fn endpointslice_service_labels() {
        let (services, pods) = slice_inputs();
        let groups = endpointslice_target_groups(&[Arc::new(sample_slice())], &services, &pods, None);
        let l = &find(&groups, "10.0.0.5:8080").labels;
        assert_eq!(l[&format!("{META_PREFIX}service_name")], "web");
        assert_eq!(l[&format!("{META_PREFIX}service_label_team")], "core");
        assert_eq!(l[&format!("{META_PREFIX}service_labelpresent_team")], "true");
    }

    #[test]
    fn endpointslice_pod_join_and_container_port() {
        let (services, pods) = slice_inputs();
        let groups = endpointslice_target_groups(&[Arc::new(sample_slice())], &services, &pods, None);
        let l = &find(&groups, "10.0.0.5:8080").labels;
        // Full pod label set is merged in.
        assert_eq!(l[&format!("{META_PREFIX}pod_name")], "web-0");
        assert_eq!(l[&format!("{META_PREFIX}pod_phase")], "Running");
        assert_eq!(l[&format!("{META_PREFIX}pod_label_tier")], "frontend");
        // Container matched by port number 8080.
        assert_eq!(l[&format!("{META_PREFIX}pod_container_name")], "app");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_port_name")], "http");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_port_number")], "8080");
        assert_eq!(l[&format!("{META_PREFIX}pod_container_init")], "false");
    }

    #[test]
    fn endpointslice_adds_additional_pod_ports() {
        let (services, pods) = slice_inputs();
        let groups = endpointslice_target_groups(&[Arc::new(sample_slice())], &services, &pods, None);
        // Slice only covered 8080; the pod's 9090 and init 7000 are added.
        let extra = find(&groups, "10.0.0.5:9090");
        assert_eq!(extra.labels[&format!("{META_PREFIX}pod_container_port_name")], "metrics");
        // Additional ports carry no endpoint labels.
        assert!(!extra.labels.contains_key(&format!("{META_PREFIX}endpointslice_endpoint_conditions_ready")));
        assert!(groups.iter().any(|g| g.targets == ["10.0.0.5:7000".to_owned()]));
    }

    #[test]
    fn endpointslice_missing_service_degrades_gracefully() {
        let (_services, pods) = slice_inputs();
        let empty_services = HashMap::new();
        let groups =
            endpointslice_target_groups(&[Arc::new(sample_slice())], &empty_services, &pods, None);
        let l = &find(&groups, "10.0.0.5:8080").labels;
        assert!(!l.contains_key(&format!("{META_PREFIX}service_name")));
        // Endpoint and pod labels are still present.
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_port_name")], "http");
        assert_eq!(l[&format!("{META_PREFIX}pod_name")], "web-0");
    }

    #[test]
    fn endpointslice_missing_pod_degrades_gracefully() {
        let (services, _pods) = slice_inputs();
        let empty_pods = HashMap::new();
        let groups =
            endpointslice_target_groups(&[Arc::new(sample_slice())], &services, &empty_pods, None);
        let l = &find(&groups, "10.0.0.5:8080").labels;
        // Endpoint/service labels present, pod labels absent.
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_address_target_name")], "web-0");
        assert_eq!(l[&format!("{META_PREFIX}service_name")], "web");
        assert!(!l.contains_key(&format!("{META_PREFIX}pod_name")));
    }

    #[test]
    fn endpointslice_second_endpoint_condition_only_when_present() {
        let (services, pods) = slice_inputs();
        let groups = endpointslice_target_groups(&[Arc::new(sample_slice())], &services, &pods, None);
        let l = &find(&groups, "10.0.0.6:8080").labels;
        assert_eq!(l[&format!("{META_PREFIX}endpointslice_endpoint_conditions_ready")], "false");
        assert!(!l.contains_key(&format!("{META_PREFIX}endpointslice_endpoint_conditions_serving")));
        // No targetRef on this endpoint, so no pod labels.
        assert!(!l.contains_key(&format!("{META_PREFIX}pod_name")));
    }
}
