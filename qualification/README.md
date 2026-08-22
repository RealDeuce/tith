# TITH qualification records

TPS‑0001 defines the normative qualification process. This directory stores
the current record for each qualified TTS revision as
`TTS-NNNN.RRR.md`. Repository history and annotated qualification tags retain
the records used by earlier baselines.

A record uses this structure:

```markdown
# Qualification: TTS‑NNNN revision R

- Candidate: TSP‑MMMM revision R at COMMIT, or existing TTS‑NNNN revision R
- Qualified document SHA‑256: DIGEST
- Evidence commit: COMMIT
- TPS revision: TPS‑0001 revision 2
- Approval: OWNER, ISO-DATE

## Normative dependencies

| Publication | Revision | SHA‑256 or exact external version |
| --- | ---: | --- |

## Conformance roles and features

| Role | Mandatory features | Optional features |
| --- | --- | --- |

## Requirement matrix

| Requirement | Role | Implementation | Positive evidence | Negative evidence |
| --- | --- | --- | --- | --- |

Use a section and paragraph reference for `Requirement`. Mark a counterpart
which has no meaningful test `Not applicable` and give the reason.

## Conformance-surface manifest

| Source item | SHA‑256 | Requirements |
| --- | --- | --- |

Include every transitive TITH-owned helper capable of affecting conformity.

## Test manifest

| Test | SHA‑256 | Requirements |
| --- | --- | --- |

## Targets, toolchains, and commands

Record every target and configuration, the normal and coverage toolchains, and
the exact commands used to build, test, and produce coverage.

## Results and coverage

Record the complete test result and the 100 percent function, line or region,
and branch coverage summaries. Include durable report digests and reproduction
commands.

## Issue audit

List the searches performed and every reviewed open issue. Confirm that only
the qualification or promotion tracking issue remains open.

## Security review

Record the applicable threat boundaries, assumptions, failure paths, and tests,
or explain why TPS‑0001 does not require a security review.

## Content-manifest verification

List each earlier evidence record reused and confirm that every input pinned by
TPS‑0001 remains byte-for-byte identical.
```

This README is a working template. TPS‑0001 remains authoritative when the
template and the process specification differ.
