# BSI-Prüfung der CI-SBOMs

Die CI-Verarbeitung prüft die maschinenprüfbaren Anforderungen der
[BSI TR-03183-2 v2.1.0](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=6)
vor dem Upload. Die Ausgabe ist CycloneDX 1.6 JSON. Das betrifft die regulären
CI-SBOMs sowie den Upload von Branch-/MR-SBOMs durch den geschützten Worker.
Das SPDX-Quellinventar des Repositorys und das Host-Agent-Inventar sind davon getrennt.

## Verhalten und Umstellung

`bsi_mode: enforce` ist der Standard. Fehlende Pflichtangaben verweigern den Upload
unabhängig von `fail_on` und vom Vorhandensein eines Leseschlüssels. Der reguläre
SBOM-Job hat jetzt `allow_failure: false`. Bestehende Integrationen müssen ihre
fehlenden Hersteller-, Lizenz- und Dateiangaben ergänzen; ein erfolgreiches
Syft-Inventar allein reicht dafür nicht aus. Template und CI-Image gemeinsam aktualisieren.

Vor dem Upload entstehen im Projektverzeichnis:

- `patchwatch-sbom.json`: die tatsächlich zum Upload vorgesehene SBOM;
- `patchwatch-bsi-report.json`: Regeln, Komponenten und fehlende Angaben, auch bei
  verweigertem Upload. `checksPassed` bezeichnet nur die implementierten Prüfungen;
  es ist keine Zertifizierung oder Zusicherung vollständiger Lieferumfangserfassung.

Beide Dateien sind Job-Artefakte, auch bei einem fehlgeschlagenen Job. `--dry-run`
führt dieselben Prüfungen ohne Upload und ohne API-Schlüssel aus. Für eine
ausdrückliche Bestandsaufnahme während der Migration kann `bsi_mode: report`
gesetzt werden: BSI-Feldlücken werden dann protokolliert und das Inventar darf
hochgeladen werden. Es ist damit **nicht als BSI-konform einzustufen**. Ungültiges
CycloneDX-JSON wird auch in diesem Modus nicht hochgeladen.

`mode: parent` und das zugehörige Service-Projekt sind Verwaltungsobjekte für
Dependency-Track. Ihr Bericht kennzeichnet sie als nicht anwendbar; ihre leeren
Dokumente sind keine Liefergegenstands-SBOMs. Die Komponenten-SBOMs müssen separat
geprüft werden. Die DTrack-Projekthierarchie ersetzt keine externe BOM-Referenz.

## Projektangaben

```yaml
include:
  - project: platform/patchwatch
    ref: v1
    file: ci-templates/sbom.yml
    inputs:
      image: registry.example.org/platform/patchwatch/ci:v1
      stage: scan
      scan_paths: dist
      sbom_creator: security@example.org
      component_creator: https://example.org/product
      distribution_license: Apache-2.0
      bsi_metadata: compliance/sbom-metadata.json
```

Die Stage `scan` muss im einbindenden Projekt existieren und nach dem Build liegen.
`dist` bezeichnet hier das tatsächliche Lieferverzeichnis, nicht pauschal den
gesamten Quellbaum. Ausschlüsse dürfen keine mitgelieferten Komponenten verbergen.

| Input | Umgebungsvariable | Bedeutung |
|---|---|---|
| `bsi_mode` | `PATCHWATCH_BSI_MODE` | `enforce` oder explizit `report` |
| `bsi_metadata` | `PATCHWATCH_BSI_METADATA` | JSON-Datei relativ zu `CI_PROJECT_DIR` |
| `sbom_creator` | `PATCHWATCH_SBOM_CREATOR` | E-Mail oder HTTP(S)-URL des SBOM-Erstellers; ohne Angabe `CI_PROJECT_URL` |
| `component_creator` | `PATCHWATCH_COMPONENT_CREATOR` | Ersteller der primären logischen Komponente; ohne Angabe `CI_PROJECT_URL` |
| `distribution_license` | `PATCHWATCH_DISTRIBUTION_LICENSE` | Geprüfter SPDX-Ausdruck der Auslieferungslizenz der primären Komponente |

Die beiden letzten Angaben gelten auch für die logischen Scan-Wurzeln eigener
Repository-Verzeichnisse. Sie werden **nicht** auf Fremdpakete oder Container
übertragen. `supplier` wird nicht als `manufacturer` interpretiert. Der globale
Lizenzausdruck wird nicht als Auslieferungslizenz sämtlicher Abhängigkeiten verwendet.

## Geprüfte Metadaten pro Komponente

Die JSON-Datei enthält optional `root` sowie `components`. `root` ergänzt die primäre
Komponente. Schlüssel unter `components` sind exakte Ausgabe-`bom-ref`s, purls oder
`file:` plus der vollständige Syft-Dateiname, zum Beispiel `file:/app/start.py`.
Der vollständige Name steht in `patchwatch-sbom.json`; der Fehlerbericht enthält
zusätzlich Namen, Version und purl. Nicht passende Selektoren sind Fehler, damit
veraltete Angaben nicht unbemerkt verschwinden.

```json
{
  "components": {
    "pkg:pypi/example@1.2.3": {
      "manufacturer": {"url": ["https://example.org/library"]},
      "licenses": [{"expression": "MIT", "acknowledgement": "concluded"}],
      "externalReferences": [
        {"type": "source-distribution", "url": "https://example.org/library/source/1.2.3"}
      ]
    },
    "file:/app/start.py": {
      "manufacturer": {"url": ["https://example.org/product"]},
      "licenses": [{"expression": "Apache-2.0", "acknowledgement": "concluded"}],
      "artifact": "dist/app/start.py",
      "properties": [
        {"name": "bsi:component:executable", "value": "executable"},
        {"name": "bsi:component:archive", "value": "no archive"},
        {"name": "bsi:component:structured", "value": "unstructured"}
      ],
      "externalReferences": [
        {"type": "distribution", "url": "https://example.org/releases/1.0/app/start.py"}
      ]
    }
  }
}
```

`artifact` ist optional. Es bezeichnet eine echte Datei innerhalb des Checkouts.
Der Generator berechnet ihren SHA-512, setzt den tatsächlichen Dateinamen und
verwendet bei fehlender Version deren Änderungszeit nach RFC 3339. Vorhandene
Versionsbezeichner bleiben erhalten. Pfade außerhalb des Checkouts, auch über
Symlinks, werden abgelehnt. Archivinhaltspfade und Image-Pfade werden niemals
gegen Dateien des Runner-Hosts aufgelöst.

Bei Verzeichnis-Scans ermittelt der Generator fehlende Dateiversionen automatisch
aus den lokalen Dateimetadaten. Für Dateien in Images müssen fehlende Versionen
oder Änderungszeiten aus dem Build beziehungsweise Image ergänzt werden. Vorhandene
SHA-512-Dateihashes werden an explizit angegebene Distribution-Referenzen übernommen.
Die Distribution-URI muss auf die tatsächlich auslieferbare Komponente zeigen;
der Generator erfindet dafür keine Download-Adresse.

Physische Dateien brauchen alle drei Klassifikationen. Das Ausführbarkeitsbit
allein reicht nicht: Auch Python-Dateien und Shared Libraries sind ausführbar im
Sinne der Richtlinie. Ob eine Binärdatei statisch eingebundene Komponenten oder
eine zerlegbare Struktur enthält, muss aus dem Build oder einer Analyse hervorgehen.
Logische Komponenten brauchen diese Dateifelder nicht.

Ein purl-Selektor darf allgemeine Ersteller-/Lizenzangaben für mehrere Instanzen
ergänzen. Instanzspezifische Änderungen an Name, Version, Typ, Hash oder `artifact`
benötigen bei Mehrdeutigkeit den einzelnen `bom-ref`. Die Aufbereitung führt
Instanzen nicht mehr zusammen.

## Lizenzen und Liefergrenze

Eine Scanner-Lizenz wird nicht automatisch zu einer geprüften Auslieferungslizenz.
Gefordert wird eine gültige SPDX-Lizenz beziehungsweise ein SPDX-Ausdruck mit
`acknowledgement: concluded`. Namen wie `Custom Licence` und unbekannte Identifier
sind Fehler. Nicht von SPDX erfasste Lizenzen müssen nach Prüfung der SPDX- und
Scancode-Listen durch einen passenden `LicenseRef-...` beschrieben werden.

CycloneDX 1.6 erlaubt nur einen Ausdruck in `licenses`. Wenn ein geprüfter
Auslieferungsausdruck die ursprünglichen Scanner-Beobachtungen ersetzt, bleiben
diese maschinenlesbar als JSON in `patchwatch:bsi:original-licenses` erhalten.
Auch diese ursprünglichen Angaben müssen gültige SPDX-Identifier/Ausdrücke verwenden;
bei Bedarf die Property explizit durch geprüfte ursprüngliche Lizenzangaben ersetzen.
So gehen ursprüngliche und Auslieferungslizenzen beim Zusammenführen nicht verloren.

Die erste Abhängigkeit außerhalb des Lieferumfangs darf nach Kap. 3.2.4 nur
identifiziert werden. Das muss bewusst pro Komponente mit der Property
`{"name":"patchwatch:bsi:scope","value":"identified"}` gekennzeichnet werden.
Sie benötigt weiterhin Ersteller, Namen, Version und vorhandene eindeutige
Kennungen. Mitgelieferte Komponenten dürfen diese Ausnahme nicht verwenden.

## Abhängigkeiten, Versionen und Grenzen

Scanner-Wurzeln, verschachtelte Komponenten, bekannte leere Abhängigkeitslisten,
Dateien, Hashes und Komponentenreferenzen bleiben erhalten. Referenzen werden
pro Scan umgeschrieben, sodass identische Scanner-IDs aus verschiedenen Images
nicht kollidieren. Enthaltensein ist gemäß Kap. 3.2.7 eine gerichtete Beziehung.
Vorhandene `compositions` bleiben erhalten; ansonsten wird die Vollständigkeit
ausdrücklich als `unknown` ausgewiesen. Unbekannt wird nicht als vollständig
ausgegeben. Die Scan-Einstellungen erfassen alle Dateien mit SHA-512, auch nicht
paketverwaltete Dateien; das erhöht gegenüber dem früheren Inventar den Umfang.

Die DTrack-Version bleibt für die Navigation ein Branch-/Tag-/MR-Slot. Die
primäre Komponente der regulären SBOM trägt bei Branches dagegen Commit-SHA plus
Inventar-Fingerabdruck, bei Tags den Release-Bezeichner. Änderungen eines Images
unter demselben Tag verändern damit bei Branch-Scans die Snapshot-Version.
Branch-/MR-Dokumente tragen den gescannten Commit beziehungsweise Merge-Tree;
der Worker verwendet den geprüften Commit als primäre Version.

**Die Prüfungen beweisen keine vollständige Lieferumfangserfassung.** Der Produzent
muss weiterhin sicherstellen, dass alle gelieferten ausführbaren Dateien und Archive,
statisch eingebundene Komponenten, Interpreter und die erste externe Abhängigkeit
erfasst sind und die Informationen dem Build entsprechen. Ein Paket-Scan kann diese
fachliche Prüfung nicht ersetzen. Die JSON-Schema-Prüfung erfolgt offline gegen
mitgelieferte offizielle CycloneDX-Schemas; Schwachstelleninformationen werden
getrennt von der SBOM verarbeitet.

## Branch-/MR-Scans

`mr-sbom.yml` und `branch-sbom.yml` unterstützen ebenfalls `bsi_metadata`,
`sbom_creator`, `component_creator` und `distribution_license`. Die Metadatendatei
wird aus jedem tatsächlich gescannten Baum gelesen, nicht aus dem aktuellen
Worker-Checkout. Die Scan-Artefakte enthalten `bsiFindings` zur Diagnose.

Der geschützte Worker prüft die Dokumente vor jedem Upload erneut. Sein
`mr-feedback.yml` unterstützt `bsi_mode`, `sbom_creator`, `component_creator` und
`distribution_license` für die von ihm erzeugte primäre Komponente. Ersteller und
Auslieferungslizenzen der Unterkomponenten müssen bereits im Scan-Artefakt stehen.
Der Worker führt keine aus dem Artefakt gelieferten Dateipfade aus. Seine SBOMs und
BSI-Berichte liegen mit versionsabhängigen Namen im Verzeichnis
`patchwatch-mr-reports/` und sind Bestandteil der bestehenden Job-Artefakte.
