# Draft rendering and nits report

Document: `draft-bradley-pqmail-certificate-bundle-00`  
Draft date: 20 November 2026  
Intended stream/status: Independent Submission / Informational

## Results

| Check | Result |
| --- | --- |
| xml2rfc 3.31.0 RFCXML validation and text/HTML generation | Passed; no document warnings or errors |
| IETF idnits3 3.3.0, submission mode, RFCXML | 0 errors, 0 warnings, 0 comments |
| IETF idnits3 3.3.0, submission mode, generated text | 0 errors, 0 warnings, 0 comments |
| Generated Markdown freshness check | Passed; Markdown matches the RFCXML source |
| XML cross-reference and rendered-section checks | Passed |
| Existing public-bundle framing and negative fixture checks | Passed; this checker does not validate cryptographic signatures |

The idnits runs enabled reference-status lookups; they were not offline runs.
Machine-readable results include input SHA-256 hashes:
[RFCXML findings](idnits-xml.json) and [text findings](idnits-text.json).
Local filesystem prefixes were removed from those reports before publication.

## Findings corrected

The first RFCXML check reported:

- `DEPRECATED_ATTRIBUTE`: the front-matter note used a `title` attribute.
  Replaced it with a `<name>` element.
- `EMPTY_AUTHOR_ORGANIZATION`: the author had an empty `<organization/>`.
  Removed the empty element.

Both findings are absent from the final check. The text check reported no nits.

## Reproduction

Use the versions pinned in `requirements.txt` and the official
[`@ietf-tools/idnits`](https://github.com/ietf-tools/idnits) package. From this
directory:

```sh
python3 render-draft.py --xml2rfc xml2rfc --cache .xml2rfc-cache
python3 render-draft.py --check
python3 check-fixture.py
idnits --mode submission --output json draft-bradley-pqmail-certificate-bundle-00.xml
idnits --mode submission --output json draft-bradley-pqmail-certificate-bundle-00.txt
```

The renderer uses the draft's explicit date and `--no-network`; its inline
references need no downloaded bibliography. Markdown is generated from the
same RFCXML and is a GitHub reading copy, not submission text. HTML and text
include xml2rfc-generated boilerplate. Do not edit the generated copies alone.

The local Python environment printed an `urllib3`/LibreSSL compatibility
warning while starting xml2rfc. This is a tooling-environment warning, not an
RFCXML finding; rendering used no network and completed successfully. The local
Node installation also produced a dependency engine-version warning during
idnits installation; both checker invocations subsequently completed normally.

## Scope and remaining review

Passing these tools is not a security audit, proof of interoperability, IETF
consensus, Internet-Draft submission, or acceptance by the Independent
Submissions Editor. The current B3 extension payload and proposed future
creation layout remain explicitly marked as proposals. Current fixed slot
bindings are not silently reinterpreted, and general smart-card support is not
claimed by a new locator name alone.

Physical-device tests of the full/losslessly compressed companion do not prove
the ultra-compact reconstruction path. Its software tests and any future
physical conversion must be reported separately. No physical ultra-compact
conversion is claimed by this report.

Before formal submission, review the cryptographic construction and parsing
rules, obtain independent implementation review, confirm algorithm-reference
revisions and extension identifiers, and complete the normal author/IPR and
Independent Submission process. No submission or legal acknowledgement was
performed by these rendering checks.
