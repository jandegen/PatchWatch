# Offline validation resources

CycloneDX 1.6 JSON schemas (`bom-1.6.schema.json`, `spdx.schema.json`,
`jsf-0.82.schema.json`) are copied unmodified from:
https://github.com/CycloneDX/specification/tree/1.6/schema

Copyright CycloneDX contributors, Apache-2.0 (see the schema `$comment`).
The SPDX identifier schema uses SPDX License List 3.23.

`license-exceptions.json` contains the `licenseExceptionId` values from
https://github.com/spdx/license-list-data/blob/v3.23/json/exceptions.json
(SPDX License List 3.23; CC0-1.0).

BSI property names and values follow BSI TR-03183-2 v2.1.0 and:
https://github.com/BSI-Bund/tr-03183-cyclonedx-property-taxonomy

Runtime validation uses only these local schemas. Updating the schemas and
identifier/exception lists requires reviewing the supported format version together.
