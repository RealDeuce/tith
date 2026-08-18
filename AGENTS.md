# TITH Contributor Guide

## Scope

This repository contains the TITH standards, a Rust reference implementation
under `crates/`, and a frozen proof-of-concept C11 implementation under
`poc/`. These instructions apply throughout the repository, including
`standards/` and the vendored `poc/hydro/` sources.

The standards describe the intended protocol. Neither reference nor prototype
behaviour is automatically normative. When code and a document disagree,
identify the disagreement and open a GitHub issue instead of silently changing
one to match the other.

## Standards Defect Workflow

Treat standards review as part of implementation. Whenever implementation,
testing, review, or interoperability work exposes a defect, contradiction,
missing requirement, or ambiguity in a TITH document, open a GitHub issue so
the normative text can be corrected. Do this during the work rather than
leaving the discovery only in chat, a commit message, or a code comment.

- Search existing open and closed issues first to avoid filing a duplicate.
- Identify the document, revision, section, and conflicting or incomplete
  requirements precisely. Explain the implementation decision that the text
  does not determine and, when clear, suggest a resolution.
- File one issue per independently resolvable standards problem. Group findings
  only when they have the same underlying defect.
- Link the issue from any temporary implementation assumption or follow-up
  work. Do not quietly make an arbitrary interpretation normative through the
  reference implementation.
- Continue implementation only when a safe, narrow, and reversible assumption
  is available; record that assumption in the issue. If the ambiguity affects
  security, wire compatibility, persistent data, or assigned values, stop that
  part of the work until the standard is resolved.
- If GitHub access or authentication prevents filing the issue, preserve the
  complete issue text locally and report the blocker rather than dropping the
  finding.
- Pass issue bodies to GitHub with real newline characters, not literal `\n`
  escape sequences. Shell and JSON quoting can double-escape multiline text;
  after creating or updating an issue, read its body back and verify that the
  Markdown contains no unintended literal newline escapes.

## Why TITH Exists

TITH is a reaction to the accumulated complexity of conventional FTN
standards.  The FTSC archive in `~/src/ftsc/`, when available, is useful
historical evidence, but it is not a design template for native TITH.

That archive shows the failure mode this project is intended to avoid: a
simple exchange distributed across overlapping documents, several accepted
representations of the same fact, corrective kludges layered onto formats that
could not express the fact directly, and requirements to emit one form while
accepting many accidental forms.  Observed legacy behaviour is relevant to a
gateway; its mere existence does not make it a desirable TITH feature.

For native TITH:

- Choose one canonical representation instead of standardizing every deployed
  variant.
- Make conforming producers and consumers follow the same grammar.  Do not
  require native parsers to guess at, repair, or preserve malformed input.
- Define byte-level framing, ordering, completion, and error behaviour in the
  document that owns them.  Avoid requirements such as "as possible" or
  "traditionally" where an implementation needs an exact answer.
- Use well-framed TLV extensibility for unknown values.  This does not mean
  accepting ambiguous or malformed encodings.
- State supersession and update cross-references when a revision changes a
  rule; do not build a hidden chain of corrections across documents.
- Keep compatibility tolerance in TSP-0003 or another explicit conversion
  boundary, not in the native transport or data model.

Interoperability here means that two conforming implementations can agree from
the standards alone, not that every implementation reproduces decades of
historical accidents.

## Standards Typography

The standards deliberately distinguish typographic marks that ASCII collapses
into `-` and `/`:

- Use U+2010 HYPHEN for ordinary compound words.
- Use U+2011 NON-BREAKING HYPHEN for document identifiers, ISO-style dates,
  UTF‑8, and number-unit compounds such as `32‑bit`.
- Use U+2013 EN DASH for ranges, U+2014 EM DASH for sentence breaks, and
  U+2212 MINUS SIGN for negative numbers in prose and mathematics.
- Use U+2044 FRACTION SLASH for displayed fractions.
- Preserve U+002D HYPHEN-MINUS, U+002F SOLIDUS, and U+005C REVERSE SOLIDUS
  when they are literal protocol syntax, filenames, DNS labels, addresses,
  URLs, escaped byte strings, or other values whose encoded bytes matter.

When editing a literal, describe the required code point explicitly rather
than substituting typographic punctuation into the literal value.

## Design Character

Read `README.md` before making protocol or architectural changes.  In
particular:

- Prefer a small, explicit protocol that is easy to implement correctly.
- Public-key authentication and server authentication are fundamental.
- Anonymous enrollment and replies to anonymous nodes use the unlisted
  address and applicant public key defined by TTS-0004 and TTS-0005.
- Do not introduce passwords, abort/resume, multiple addresses per connection,
  optional security, or compatibility machinery.
- Do not impose arbitrary protocol limits.  Platform overflow checks,
  allocation failures, malformed lengths, and local resource policy are not
  arbitrary limits and must still be handled safely.
- Legacy FTN behaviour belongs at an explicit conversion boundary.  Do not let
  it complicate the native TITH representation or transport.

The project is deliberately opinionated.  Preserve that directness, but make
wire requirements exact enough that two independent implementations do not
need to guess.

## Protocol Model

- TTS-0002 defines the unsigned TLV integer encoding, TTS-0007 defines signed
  integers in terms of it, and TTS-0003 defines the common TLV types and
  signed containers.
- A Bundle begins with an Origin, a PublicKey when that Origin is the
  unlisted address, and a Header SignedTLV containing Destination, a
  PublicKey when that Destination is the unlisted address, and Timestamp.
  Every payload SignedTLV begins with the hash of that exact Header SignedTLV,
  followed by request data as specified by TTS-0005.
- The unlisted address is not unauthenticated.  Its supplied key proves
  possession and identifies the system but cannot override the nodelist key
  for a listed address.  Held values for an unlisted next hop are selected by
  their local PublicKey association, which does not change an enclosed
  Message's ultimate Destination PublicKey.
- Enrollment uses ordinary signed Messages and PollMessages.  Transport
  Accepted means the application Message was stored, not that membership was
  approved.  Approval is the publication of a nodelist entry containing the
  same public key, as described nonnormatively in TRD-0002.
- The reserved `p2p` domain uses the unlisted address permanently and has no
  nodelist.  TRD-0003 describes one possible peer-network organization;
  bootstrap and routing algorithms remain separate concerns.
- The Client drives the exchange and performs the active close.  The Server
  does not send FIN to mark the end of its response.
- A Client keeps its write side open when its Bundle contains a FileRequest or
  Poll because returned values may require a Reply Bundle.
- A Reply Bundle responds to exactly one Bundle.  Each applicable request has
  exactly one Accepted or Rejected response, in request order.
- A Reply Bundle reverses the transport identities: its Origin is the original
  Bundle's Destination, and its Destination is the original Bundle's Origin.
- Values returned by an accepted Poll or FileRequest are in the same SignedTLV
  as its Accepted value.  They may occur in any order; the SignedTLV provides
  their boundary, so a separate count is unnecessary.  An accepted
  FileRequest may return zero or more Files.
- The Client already knows how many responses it expects.  Once every
  SignedTLV containing an outstanding Accepted or Rejected response has been
  completely received and authenticated, the Server's turn is complete; the
  Client must not wait for Server FIN.
- Accepted and Rejected values are inside the Reply Bundle.  They are not
  transport frames and do not justify adding a separate end marker.
- The Server may process and answer validated signed data while the Client is
  still sending.  Do not add a whole-bundle buffering requirement casually.
- SignedData must be authenticated before its contents are processed or acted
  on.  Limited parsing of unauthenticated data is allowed only where the
  enclosing protocol explicitly requires it for error reporting.
- Messages and standalone Files carry end-to-end item signatures.  A File
  inside a Message may rely on the enclosing Message signature instead.
- NetMail has a Destination and no Area; Echomail has an Area and no
  Destination.  This lets Echomail replicate without rewriting a signed,
  peer-specific destination.
- Nodelist public keys are part of the authentication trust path, not merely
  connection metadata.

Do not add a Bundle wrapper, `EndOfBundle` value, handshake, or negotiation
layer without first demonstrating a protocol state that the existing TLV
lengths and outstanding-response accounting cannot resolve.

## Source Map

- `crates/tith-crypto` is the only Rust crate permitted to call libhydrogen.
  Audited Windows host-binding modules in `tithd` and `tith-submit` may also
  contain the `unsafe` blocks required by the raw Win32 API; portable modules
  remain safe Rust.
- `crates/tith-wire`, `tith-nodelist`, and `tith-exchange` implement the
  normative TTS protocol layer.
- `crates/tith-config` and `tith-router` implement local routing policy.
- `crates/tith-store` owns durable database layout and transactions. Callers
  must not depend on its redb table representation.
- `crates/tith-ipc` owns canonical local IPC text; binding code carries those
  bytes without inventing another grammar.
- `crates/tith-submit` owns the command-line IPC client, the reusable client
  bindings, and the binding-independent conformance check.
- `crates/tithd` is the blocking reference service and contains host bindings.
  Its native mail listener accepts only operations whose wire grammar and
  durable behavior are implemented; unsupported work receives an explicit
  response rather than being discarded.
- `poc/tith.c` handles command-line dispatch and key generation.
- `poc/tith-common.c` owns TLV parsing, construction, signing, validation, and
  process-wide cleanup state.
- `poc/tith-client.c` and `poc/tith-server.c` contain the current exchange
  prototype.
- `poc/tith-interface.h` is the host transport and filesystem boundary;
  `poc/tith-stdio.c` and `poc/tith-xsi.c` provide standalone implementations.
- `poc/tith-config.c` loads node identities and nodelists.
- `poc/tith-nodelist.c` is the reusable nodelist parser;
  `poc/nodelist.c` is the conversion utility.
- `poc/tith-bundle.c` is an incomplete outbound scanner and bundler.
- `standards/TTS-*.txt` are normative standards, `standards/TSP-*.txt` are
  proposals, and `standards/TRD-*.txt` is supplemental background.
- `poc/hydro/` is vendored libhydrogen.  Avoid modifying it for TITH-specific
  behaviour.

## C Style and Error Handling

The rules in this section apply to the historical C code only. Do not extend
the C proof of concept to implement new reference-mailer features.

- All TITH-owned code except the host-supplied transport, logging, and
  filesystem callbacks declared in `poc/tith-interface.h` MUST be strict ISO
  C11 and MUST use only functions, types, and macros specified by the C11
  standard.  Do not call POSIX, BSD, GNU, platform, or compiler-specific APIs
  outside those callback implementations.  `TITH_main()` is portable core
  code despite being declared in `poc/tith-interface.h` and is not exempt.
- Host callback implementations may use the APIs required to provide their
  services.  Keep those details in the interface implementation; do not
  expose platform types or semantics to portable callers.  The interface
  declarations themselves remain portable C11.  Vendored `poc/hydro/` code
  follows its upstream portability model and is not a reason to introduce
  extensions into TITH-owned portable code.
- Follow the existing layout: tabs for indentation, return type on the line
  before a function name, braces on their own line for functions, and braces
  around multi-statement control bodies.
- Prefer small local changes over new abstraction layers.
- Fatal protocol and allocation errors go through `tith_logError()` and the
  established `setjmp()`/`longjmp()` boundary.
- `tith_logError()` transfers control; top-level error paths perform cleanup.
  Do not clean the same resource on both sides of the jump.
- Follow the allocation and `FILE *` stack discipline in `poc/tith-common.c`
  so an error jump can release partially constructed state.
- Check every transport callback result.  Treat short reads, failed writes,
  failed flushes, and declared lengths beyond their container as errors.
- Check integer conversions and allocation-size arithmetic before using an
  untrusted TLV length.
- Preserve the `thread_local` state model unless deliberately redesigning the
  embedding API.  It supports one active `TITH_main()` invocation per thread;
  connections on separate threads are independent, but same-thread re-entry
  and moving an active connection between threads are unsupported.
- Interface callbacks execute synchronously on the thread running
  `TITH_main()`.  They must not re-enter TITH, and implementations must
  synchronize any state shared by callbacks for concurrent connections.
- Concurrent connections require a libhydrogen target on which its `TLS`
  storage qualifier is non-empty.  Do not assume every libhydrogen platform
  provides that guarantee.
- Use the exact libhydrogen key and signature sizes and the contexts named by
  the standards.  Never continue with a missing key or failed signature.
- Reject unsupported behaviour clearly instead of logging a fallback that the
  implementation cannot actually perform.

## Editing Standards

Read every directly related standard in full before changing normative text.
Also check its references in the other local documents and the implementation's
type assignments.

- Use `MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` deliberately.
- State hierarchy, ordering, cardinality, and completion conditions explicitly.
  Words such as "followed by" must make clear whether values are siblings or
  children.
- Preserve the plain-text document format, headings, box drawing characters,
  indentation, and approximately 72-column wrapping.
- Keep Contents entries, section numbers, type names, and cross-references in
  sync.
- Do not assign a permanent TLV type casually.  Check TTS-0003, TTS-0005, and
  `poc/tith.h` for existing and reserved ranges.
- Examples illustrate normative rules; they must not introduce a second,
  contradictory grammar.
- Do not turn non-conforming native behaviour into a normative compatibility
  requirement merely because an implementation has shipped it.  Correct the
  implementation or describe tolerance as local policy.
- Use FTSC documents to establish legacy conversion facts, and cite the exact
  document and revision when that distinction matters.  Do not import their
  optional dialects into native TITH.
- TSP documents may retain an informal and opinionated rationale, but any
  proposed wire or file syntax still needs deterministic parsing rules.

## Build and Validation

For Rust changes, run all of:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Rust code uses stable Rust 1.97.1, edition 2024, workspace dependencies, and
the repository `rustfmt.toml`. Keep public protocol types strongly typed and
keep platform code at binding boundaries. Do not add another unsafe crate.
Use streaming APIs for untrusted or potentially large protocol values and
offer owned convenience APIs only where they do not become a hidden limit.

The reference store uses pure-Rust redb. Do not introduce SQLite or another C
database dependency. libhydrogen remains isolated in `tith-crypto` until its
cryptographic compatibility can be replaced deliberately.

Use the strict build for development:

```sh
gmake -C poc DEBUG=1
```

The normal optimized build is `gmake -C poc`.  Make does not track a change
between debug and optimized flags, so use care when switching modes.  Do not
commit generated binaries, objects, dependency files, local configuration, or
`TITH-*` fixtures.

There is not yet a complete automated test suite.  Validate changes in
proportion to their scope:

- Run `gmake -C poc DEBUG=1` and introduce no new warnings.  Existing warnings
  from a clean rebuild of vendored libhydrogen are outside normal TITH changes.
- Exercise a connected Client and Server for signing and parsing changes.
- Exercise truncated input, invalid nested lengths, missing keys, and I/O
  failure paths when touching common TLV or transport code.
- Run sanitizer builds for parsing, ownership, or buffer changes when practical.
  LeakSanitizer is not supported on every target used by this tree.
- Run `git diff --check -- .` before handing work back.

The checkout may contain unrelated local changes.  Inspect status with
`git status --short -- .`, preserve unrelated work, and do not clean or commit
unrelated files.
