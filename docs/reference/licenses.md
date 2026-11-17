# Lizenz und SPDX

Eigener Quellcode und Deployment-Dateien: **Apache-2.0**, vollständiger Text in `LICENSE`,
Hinweis in `NOTICE` und `SPDX-License-Identifier` in den Code-/Scriptdateien.
Die maschinenlesbare Projektinventur ist **`patchwatch.spdx.json` (SPDX 2.3, JSON)**.
Sie enthält das Projekt selbst, Dateiliste, SHA-1/SHA-256-Prüfsummen,
Package Verification Code, Lizenzdeklaration und Beziehungen zu den eingesetzten Komponenten.
Das SPDX-Dokument selbst verwendet die vom SPDX-Format vorgeschriebene Datenlizenz `CC0-1.0`.
Diese ändert die Projektlizenz nicht.

```sh
python3 scripts/spdx.py
python3 scripts/spdx.py --check
```

Der Generator erfasst versionierte und noch nicht ignorierte Quelldateien. Das SPDX-Dokument
selbst ist wegen der Prüfsummen-Selbstreferenz ausgeschlossen. Ignorierte Secrets, virtuelle
Umgebungen und Build-Artefakte werden nicht erfasst. Die CI prüft die genaue Inventur.
Dokument-Namespace und Package Verification Code hängen reproduzierbar vom Quellstand ab;
das Erstellungsdatum ist auf den Projektbeginn gesetzt. Projektversion: `1.0.5`.

| Fremdkomponente | Deklarierte Lizenz |
|---|---|
| Syft | Apache-2.0 |
| Docker CLI | Apache-2.0 |
| Trivy | Apache-2.0 |
| Dependency-Track API / Frontend / offizielles Helm-Chart | Apache-2.0 |
| PostgreSQL | PostgreSQL |
| Python | Python-2.0 |
| nginx-unprivileged Container-Buildskripte | Apache-2.0 |

Die SPDX-Pakete beschreiben **deklarierte Deployment-Abhängigkeiten**, deren Dateien nicht
als analysiert ausgegeben werden. Container-Basisbetriebssysteme und transitive Fremdpakete
sind nicht vollständig Bestandteil dieser Quellinventur. Die Lizenz des nginx-Binaries selbst
ist BSD-2-Clause; sie ist von den Apache-lizenzierten Container-Buildskripten zu unterscheiden.
Für Distribution von Container-Images zusätzlich eine Image-SBOM mit Syft erzeugen und
Lizenztexte der enthaltenen Pakete mitführen. OSV/GitHub/NVD-Daten und optionale Integrationen
haben eigene Datenlizenzen/Nutzungsbedingungen. Es wird kein Fremdquellcode ins Repository kopiert.


## Lizenzinventar der Entwickler-Rechner

Die Projekt-SPDX beschreibt Patchwatch selbst. Die Lizenzen der installierten Software
werden separat mit jeder Host-SBOM nach Dependency-Track übertragen.

Der Agent übernimmt von Syft erkannte SPDX-Lizenz-IDs, kurze Lizenznamen und SPDX-Ausdrücke.
Bei VS-Code-Erweiterungen wird zusätzlich eine kurze Lizenzangabe aus dem Manifest übernommen,
sofern vorhanden. Die übrigen Erweiterungsleser ergänzen derzeit keine Lizenzmetadaten.
`AND`, `OR` und `WITH` bleiben erhalten; daraus wird keine eigene rechtliche Bewertung
abgeleitet. Lizenztexte, URLs und Angaben zu individuellen Lizenzgebern werden entfernt.
Mehrfach erkannte Paketkopien bleiben dieselbe Komponente; fehlende Lizenzangaben in einer
Scan-Wurzel überschreiben keine bereits vorhandenen Angaben aus einer anderen Wurzel.
Unterschiedliche Ausdrücke für dieselben Paketkoordinaten werden nicht automatisch mit
`AND` oder `OR` kombiniert; die erste Angabe bleibt erhalten und die Komponente bekommt
`patchwatch:license-conflict=true` zur manuellen Prüfung.

Ohne erkannte Lizenz bleibt die Angabe unbekannt. Insbesondere erhalten Fremdpakete **nicht**
automatisch die Apache-2.0-Lizenz von Patchwatch. Erkennungsabdeckung und Korrektheit hängen von
den Paketmetadaten und den konfigurierten Scan-Wurzeln ab. Ein maschinell erkanntes Lizenzlabel
ist kein Nachweis, dass alle Lizenzpflichten erfüllt sind.

In DTrack stehen diese Angaben bei **Projekte → Hostname → Komponenten** in der Lizenzspalte
bzw. im Komponentendetail. Die globale Lizenzansicht enthält den SPDX-Lizenzkatalog und ist
kein Beleg für vollständige Zuordnung der Hostpakete.

Die automatisch verwalteten Regeln umfassen eine Lizenz-Policy für fehlende/nicht auflösbare
Angaben (`WARN`), die High-/Critical-Security-Policy (`FAIL`) und weitere
[Security-/Lizenzregeln](../configuration/policies.md#aktive-grundregeln). Das Release-Profil verwendet die
verwaltete Lizenzgruppe `Patchwatch distribution baseline`; Hostprojekte erhalten dieses
Profil nicht automatisch. Lizenzkonflikte erscheinen zusätzlich im Compliance-Bericht. Definition, Freigabelisten,
Ausnahmen und Bericht/Gates sind in der [Policy-Anleitung](../configuration/policies.md) beschrieben.
Eine organisationsspezifische Allow-/Deny-Liste wird erst mit ausdrücklichen Vorgaben ergänzt.

Referenz: [DTrack License Evaluation](https://docs.dependencytrack.org/analysis-types/license/).
