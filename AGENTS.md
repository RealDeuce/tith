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

An issue is closed by the commit which resolves it, using a `Closes #N` trailer,
and by nothing else. Never run `gh issue close`, and never close an issue
through the web interface. This applies to every issue, not only a standards
defect, and it holds even when the work is finished and verified: the commit is
what records why the issue closed and what closed it, and closing by hand
separates the two and closes the issue before the commit is pushed or reviewed.
Comment on an issue freely; resolving it is the commit's job.

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
- A standalone File is addressed the same two ways, but only one of them is in
  the item.  A distribution File carries an Area, Via, and SeenBy; a
  peer-addressed File carries none of the three and is addressed solely by the
  Bundle Destination, as is a FileRequest.  Neither can therefore be routed or
  relayed: a node given one in a Bundle addressed to itself takes it as its own,
  so its Destination is always also its next hop.
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
  bindings, and the binding-independent conformance check. Its CLI is the
  `cli` module rather than a binary; `tith` reaches it.
- `crates/tith-nodelist-legacy` converts an FTS-5000.005 nodelist to TTS-5000.
  It is a legacy conversion boundary and must not be folded into
  `tith-nodelist`, and it must not depend on it.
- `crates/tith-message-legacy` reads and writes the TSP-0003 section 4 stored
  `.msg`, the section 5 packed message, and the section 6 Type-2+ packet, and
  resolves attachment disposition. It has no dependencies at all, so the native
  field mapping belongs to `tith-adapter` and never here. It is likewise a legacy boundary and must
  not depend on the native protocol layer. The two post-send conventions,
  FTS-5005.003 Subject FileSpec prefixes and FSC-0053.002 FLAGS `KFS`/`TFS`,
  differ in granularity as well as syntax and are never inferred from the
  bytes; the caller states which applies. `K/S` is the message, not its
  attachments.
- `crates/tith-bso` owns the FTS-5005.003 Binkley Style Outbound layout, flow
  file naming and flavour order, reference files, request lists, and the `.bsy`
  and `.hld` control files. It is a legacy boundary like the two crates above. It
  follows FTS-5005 as written rather than any one implementation's documented
  limitations: derived names are matched in either case, and the default zone
  is searched under both the bare root and its zone-suffixed form. A `.req` has
  no flavour letter of its own, so it is classified before the flavour and
  signature are split apart.
- `crates/tith-ledger` is the TSP-0013 section 2 private durable adapter
  ledger. It records the intended conversion and generated names before
  publication, and its state ordering is what recovery uses; it must never be
  made to depend on a legacy pathname, scan order, timestamp, or disappearance
  as proof of a native IPC result.
- `crates/tith-adapter` is the one crate permitted to see both sides, because
  the TSP-0003 field mapping needs `tith-wire` for native items and
  `tith-message-legacy` for legacy objects while neither may depend on the
  other. It owns the TSP-0013 placement, transaction, and ownership boundary:
  conversion in both directions, the section 3.1 byte-exact self-check,
  section 5 publication, TIC generation, the TSP-0011 section 5.1 policy, and
  the FSC-0086.001 request-processor boundary. A conversion which cannot be
  represented is refused, never made lossy, and a step blocked on standards
  work fails loudly naming its issue rather than degrading silently.
  That self-check is what makes TTS-0005 keep one native representation of each
  legacy fact: an absent `LegacyAttributes` or `TimestampOffset` is the only form
  of a zero one, attachment presence lives in the `File` children rather than in
  AttributeWord bit 4, and `MessageText` is paragraphs each terminated by one
  U+000A with no U+000D. Legacy always carries the attribute word in a fixed
  field, canonical output always emits `TZUTC`, and FTS-0001.016 makes a hard
  carriage return the end of a paragraph rather than a separator between two, so
  a second native form would simply be unreconstructable. Enforce those rules
  where a Message is minted, in `build_originated_message`; never in
  `validate_message`, because a received item's authentication is its signature
  and not its conformance to a canonical field list. An Application is not held
  to them: TSP-0006 has the service supply a missing `MessageText` terminator.
  A claimed FileRequest is answered rather than published: the processor decides
  which files the peer may have, and each becomes a TSP-0006 `Job Peer-File`
  addressed back to it, keyed on InboundID so a redelivery does not send twice.
  The response markers map only as far as TSP-0006 can promise — `=` is Delete,
  which fires after confirmed delivery, and `-` asks for erasure whatever
  happens, which has no native disposition, so it stays Keep and the adapter
  removes the file itself. That removal is recorded in the ledger before the
  submission which makes it owed and cleared only when every path is gone, so an
  interrupted run recovers it; section 3 requires it be recorded rather than
  remembered. "In any case" is not conditional on the file being sent, so a `-`
  file the request's condition excludes is still owed. A node with no configured
  processor will never serve a request, so it rejects one rather than deferring
  it forever.
- `crates/tith` is the client multiplexer binary. It carries no protocol logic
  and only dispatches subcommands. `tith-submit` is installed as a link to it,
  so the file stem of `argv[0]` may select the submit client directly; keep
  dispatch an exact match with no abbreviations or aliases.
  `tith netmail scan` is safe to run concurrently with itself and must stay
  that way. Every gate is a create that fails when the name is taken — the
  claim, the restore, and the publish alike — and it never checks existence
  before creating. A rename cannot be one of those gates: POSIX `rename(2)` is
  name based, but Rust's Windows `fs::rename` opens a handle and renames the
  file object, so every racer succeeds and every racer believes it won. It must
  not retire a legacy object before a Committed result, and treats a duplicate
  submission as preferable to a lost or corrupted message.
  `tith bso scan` holds the same invariant through the `.bsy` lock, which is
  taken with an exclusive create and released on every exit path. It reads an
  outbound and submits from it; it never lays one down. It deletes a packet and
  rewrites a reference file or request list only after Committed, and never
  deletes or truncates a referenced payload — that directive is carried to the
  service as a `Source-Disposition` and performed there, after delivery.
  A reference entry no message claims and no TIC accompanies is a peer-addressed
  standalone File, and a `.req` action is a FileRequest. Both need a Destination,
  which needs `--domain`; without one they are reported and left in place rather
  than addressed by guesswork. The Hold flavour becomes `Next-Hop Passive` so
  "wait for their poll" survives the conversion.
  `tith inbound run` is the same boundary in the other direction. It publishes
  every object under a private staging name and then an exclusive create which
  never replaces an existing file, publishes companions before the object that
  names them, and acknowledges an item only after its objects and the ledger
  state which transfers responsibility are durable. It must not append to an
  already published packet: TSP-0013 section 5 forbids replacing a published
  object, and a tosser reads and deletes packets without any lock.
  An `EchoMail` or file distribution item owes onward copies. The default is to
  discharge that natively with a TSP-0006 `Job Forward` while the claim is
  current, because that preserves the exact signed bytes and leaves the legacy
  object terminal. Leaving the fan-out to the tosser is configurable and
  permitted, but a message re-entering TITH from a legacy area has no TITHSIG
  and is re-imported as `SignedOrigin-Valid` whatever it was, so an item known
  to be modified in transit becomes gateway-attested; do not make that the
  default. An item TSP-0006 section 6 will not forward owes no native copy.
- `crates/tithd` is the blocking reference service and contains host bindings.
  Its native mail listener accepts only operations whose wire grammar and
  durable behavior are implemented; unsupported work receives an explicit
  response rather than being discarded.
  `accept` owns turning an authenticated item into a stored item and a
  response. Both the listener and the outbound driver dispatch through it,
  because TSP-0002 draws no distinction between an item a peer sent and one a
  poll returned: the same authorization applies and the same response is owed.
  It also owns relay. A NetMail for anyone else goes straight to the spool and
  never becomes an inbound item, because a hub must transit mail with no
  application running. Relay defaults to denied: the first `Allow-Relay` or
  `Deny-Relay` whose three selectors match decides and no match refuses, so
  relaying is something an operator turns on rather than off. Only an
  `Origin-Valid` or `SignedOrigin-Valid` item may be relayed. A refusal is
  answered to the peer and logged, never raised and never dead-lettered here;
  responsibility stays with the sender, whose origin can notify a user, while a
  store failure is raised so the peer retries instead of being told the item is
  permanently unacceptable. Only the routing suffix is rebuilt — the signed
  region is carried through byte for byte — and the spool key is the signed-item
  identity rather than the bytes, because a retransmission is never
  byte-identical but its identity never changes.
  `framing` owns reading a Bundle prefix and is likewise shared, so the two
  ends of an exchange cannot drift apart in how they frame a Header.
  `schedule` owns TSP-0002 section 8 timing and nothing else; which work an
  activation selects belongs to its caller. `Start Local` requires an explicit
  offset rather than guessing, because safe portable Rust cannot read the host
  civil offset and treating local time as UTC would move every schedule.
  `deliver` owns the outbound connection. A connection carries only compatible
  copies — the same local AKA and the same exact next-hop identity, including
  the `PublicKey` when unlisted — and must never combine copies from different
  local AKAs. Every claimed copy gets an outcome on every exit path, and a
  connection which fails leaves its copies eligible rather than invoking
  permanent failure policy; losing a claim is worse than sending twice. A poll
  snapshot is claimed atomically or not at all, and a held copy stays claimed
  until the peer says what became of it.
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
