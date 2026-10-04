# Documentation contracts

F-Layer adopts the [Fuzzy Technologies documentation blueprint](https://github.com/Fuzzy-Technologies/FuzzyRoutines/tree/develop/docs/documentation-blueprint):
MkDocs Material, mkdocstrings-python, and Griffe with static discovery from an
installed wheel. The theme is extended through tracked configuration, CSS,
and SVG assets. Generated HTML remains disposable and untracked.

## API discovery

Every Python module in the installed `flayer` package receives a generated API
page. Discovery reads Python syntax and never imports the runtime package. An
import guard makes an attempted package import fail the build. Package modules
and public definition anchors are checked against generated HTML; each page
links to its corresponding `develop` source.

Authored English pages use the tracked locale unit registry. Dynamically
generated API units use a disposable inventory with the same stable symbol
IDs and versioned source hashes. Their target-language states are explicitly
`missing`; this generated inventory cannot manufacture a translation or review.

## Language and review

English is canonical. Russian and Simplified Chinese currently have explicit
untranslated fallback routes. Language navigation never labels English content
as an approved translation.

A translated unit requires a stable unit ID, matching canonical source hash,
a translation path, and accountable editorial/technical human reviews before
`approved` is valid. Automation may detect drift and emit `missing` records;
it never creates approvals. Terminology lives in aligned locale glossaries.

## Publication

Pull requests and `develop` produce downloadable preview and evidence artifacts.
Only a `push` event for the `master` branch may deploy the verified Pages
artifact. Documentation publishing is separate from package publication.

The public routes are `/F-Layer/en/`, `/F-Layer/ru/`, and `/F-Layer/zh-CN/`.
The root opens the English reference. No immutable release documentation is
claimed before a stable release exists.

[ADR 0004](https://github.com/Fuzzy-Technologies/F-Layer/blob/develop/docs/adr/0004-documentation-platform.md)
records the accepted generator, review, source-hash, fallback, and publication
boundaries.
