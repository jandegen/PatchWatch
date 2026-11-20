# Open TODOs

## NeuVector integration – open, explicitly not yet implemented

The static [Compose service collection](../usage/services.md) is implemented. It reads local
service definitions but does not observe running workloads or communication relationships.

Goal for a later extension: supplement the Kubernetes service inventory with NeuVector metadata
and optionally observed service dependencies and transfer it as CycloneDX services
to Dependency-Track.

- [ ] Check the API contract of the NeuVector version in use; provide read-only access exclusively.
- [ ] Assign workloads stably via cluster, namespace and controller; avoid short-lived pod IDs.
- [ ] Merge Kubernetes services/ingresses with detected protocols and ports.
- [ ] Merge `services.generated.yaml` with optional manual overrides.
- [ ] Make observed communication relationships a separate opt-in and agree on the data scope;
      do not adopt usage statistics, payloads or credentials.
- [ ] Optionally design a separate bridge input for NeuVector webhooks with its own authentication
      and deduplication; send no NeuVector payloads to the existing DTrack input.
- [ ] Define retention periods, vanished services, RBAC, tests and operating effort.

Status: there is no NeuVector collector, no API credentials, no enabled webhooks
and no automatic service export from NeuVector into Patchwatch. The implementation is deferred in favor of the
native Trivy integration in Dependency-Track.

References: [REST API](https://open-docs.neuvector.com/automation/automation/),
[Network Activity](https://open-docs.neuvector.com/navigation/navigation/).
