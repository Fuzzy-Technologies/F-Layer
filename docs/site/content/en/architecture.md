# Architecture

F-Layer has implemented configuration/state, generic provider boundaries,
durable lifecycle/recovery, scoped Yandex translation, secure-gateway artifacts,
and bounded diagnostics. The [installed API reference](api/index.md) lists the
public contracts present in this revision, including the executable CLI module.

| Boundary            | Responsibility                                                                                      |
| ------------------- | --------------------------------------------------------------------------------------------------- |
| Configuration       | Validate explicit user intent and identity without embedding credentials.                           |
| State               | Preserve owned locators and committed lifecycle evidence.                                           |
| Provider            | Own cloud translation, scope validation, and capability discovery.                                  |
| Deployment profile  | Compile an infrastructure outcome into provider-neutral plans and artifacts.                        |
| Lifecycle           | Journal mutation intent, reconcile observations, persist state, and recover interrupted operations. |
| Diagnostics         | Produce bounded, redacted health and benchmark evidence.                                            |
| Generated artifacts | Enforce ownership, provenance, and explicit removal rules.                                          |

The [implemented architecture reference](../../../architecture/reference.md)
contains composition, recovery, and documentation diagrams. The
[architecture index](../../../architecture/README.md) links each stable contract;
the [ADR index](../../../adr/README.md) records accepted decisions and alternatives.
Future extension and integration behavior requires its own explicit contract.

## Evidence and scope

[Documentation coverage](../../../development/documentation-coverage.md)
accounts for every tracked file without claiming that tests, tools, or private
helpers are consumer APIs. Static discovery checks the entire installed package
against source. API anchors, all canonical Markdown routes, and reachability
from the English entry page are verified before publication.

Credentials and real resource state never become documentation fixtures.
