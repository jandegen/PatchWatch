# Offene TODOs

## NeuVector-Anbindung – offen, ausdrücklich noch nicht umgesetzt

Die statische [Compose-Service-Erfassung](../usage/services.md) ist umgesetzt. Sie liest lokale
Dienstdefinitionen, beobachtet aber keine laufenden Workloads oder Kommunikationsbeziehungen.

Ziel für einen späteren Ausbau: Kubernetes-Serviceinventar durch NeuVector-Metadaten
und optional beobachtete Dienstabhängigkeiten ergänzen und als CycloneDX-Services
an Dependency-Track übertragen.

- [ ] API-Vertrag der eingesetzten NeuVector-Version prüfen; ausschließlich lesenden Zugang vorsehen.
- [ ] Workloads über Cluster, Namespace und Controller stabil zuordnen; kurzlebige Pod-IDs vermeiden.
- [ ] Kubernetes-Services/Ingresses mit erkannten Protokollen und Ports zusammenführen.
- [ ] `services.generated.yaml` mit optionalen manuellen Overrides zusammenführen.
- [ ] Beobachtete Kommunikationsbeziehungen separat opt-in gestalten und Datenumfang abstimmen;
      keine Nutzungsstatistiken, Payloads oder Zugangsdaten übernehmen.
- [ ] Optional einen eigenen Bridge-Eingang für NeuVector-Webhooks mit eigener Authentifizierung
      und Deduplizierung entwerfen; keine NeuVector-Payloads an den bestehenden DTrack-Eingang senden.
- [ ] Löschfristen, verschwundene Dienste, RBAC, Tests und Betriebsaufwand festlegen.

Status: Es gibt keinen NeuVector-Collector, keine API-Zugangsdaten, keine aktivierten Webhooks
und keinen automatischen Service-Export aus NeuVector in Patchwatch. Die Umsetzung ist zugunsten der
nativen Trivy-Anbindung in Dependency-Track zurückgestellt.

Referenzen: [REST API](https://open-docs.neuvector.com/automation/automation/),
[Network Activity](https://open-docs.neuvector.com/navigation/navigation/).
