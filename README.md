# TITH

> This Isn't That Hard.

[![Rust](https://github.com/RealDeuce/tith/actions/workflows/rust.yml/badge.svg)](https://github.com/RealDeuce/tith/actions/workflows/rust.yml)
[![Standards site](https://github.com/RealDeuce/tith/actions/workflows/pages.yml/badge.svg)](https://realdeuce.github.io/tith/)

TITH is a modern store-and-forward protocol for FidoNet Technology Networks.
It combines a small set of versioned standards with a Rust reference mailer,
with the goal of making secure FTN transport straightforward to implement and
interoperate with.

The project starts from a deliberately simple premise: define one canonical
representation, authenticate every peer and payload, and keep legacy
conversion at an explicit boundary instead of carrying historical ambiguity
into the native protocol.

## Start here

- Read the [published standards archive](https://realdeuce.github.io/tith/).
- Browse the [normative source documents](standards/).
- Follow implementation work in the [issue tracker](https://github.com/RealDeuce/tith/issues).
- Explore the Rust reference implementation under [`crates/`](crates/).

TITH documents use three publication classes:

- **TTS** — accepted TITH Technical Standards.
- **TSP** — Standards Proposals still subject to change.
- **TRD** — Reference Documents providing rationale and background.

## Design principles

TITH is designed around a few firm constraints:

- canonical TLV framing and integer encodings;
- mandatory public-key authentication for nodes and bundles, with explicit
  end-to-end item authentication states;
- authenticated unlisted identities for enrollment and peer-to-peer use;
- a nodelist-backed trust path for listed nodes;
- explicit routing, durable acceptance, polling, and local IPC semantics;
- no arbitrary protocol limits; and
- no passwords, optional security, transport negotiation, or native legacy
  compatibility modes.

Legacy FTN formats still matter, but they belong in adapters. Native TITH
producers and consumers should not need to guess which accidental wire format
another implementation meant.

## Project status

TITH is under active development. The core standards cover canonical values,
addresses, signed bundles, exchange behavior, and the distribution nodelist.
The Rust workspace implements those foundations plus configuration, routing,
durable storage, and local IPC building blocks.

The reference daemon is not yet a production mailer, but it now exchanges mail
in both directions: a native listener with durable local Message, standalone
File, and FileRequest acceptance, duplicate handling, and authenticated replies,
a schedule-driven outbound driver that delivers queued copies and polls its
peers, and NetMail relay so a node can act as a hub or a boss. File requests are
served through an external FSC-0086.001 processor rather than internally. The C
implementation under [`poc/`](poc/) is a frozen historical proof of concept; new
implementation work belongs in Rust.

## Rust workspace

The implementation is divided by responsibility rather than by document:

| Crate | Responsibility |
| --- | --- |
| `tith-crypto` | Libhydrogen keys, signatures, hashes, and encrypted transport primitives; the only crate permitted to use `unsafe` |
| `tith-wire` | Canonical integers, addresses, TLVs, Bundles, and payload items |
| `tith-nodelist` | TTS-5000 nodelist parsing, endpoints, and public-key lookup |
| `tith-nodelist-legacy` | FTS-5000.005 to TTS-5000 nodelist conversion |
| `tith-message-legacy` | Legacy stored `.msg`, packed messages, and Type-2+ packets, read and written |
| `tith-bso` | FTS-5005 Binkley Style Outbound layout and control files |
| `tith-ledger` | The TSP-0013 durable adapter ledger |
| `tith-adapter` | TSP-0013 conversion, publication, TIC, and request-processor boundary |
| `tith-exchange` | Blocking TTS-0006 exchange state and response tracking |
| `tith-config` | Canonical reference-mailer configuration parsing |
| `tith-router` | Deterministic route selection and commitment |
| `tith-store` | Pure-Rust `redb` durable state and atomic claims |
| `tith-ipc` | Canonical local IPC request and result documents |
| `tith-ipc-tcp` | TSP-0009 authenticated key exchange and encrypted IPC records |
| `tith-submit` | TSP-0006 command-line client and reusable clients for every IPC binding |
| `tith` | The `tith` client multiplexer binary |
| `tithd` | Reference service and host bindings |

Rust 1.97.1 is pinned by [`rust-toolchain.toml`](rust-toolchain.toml). To build
and validate the complete workspace:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo doc --workspace --no-deps
```

## Trying the reference service

Validate a TSP-0002 configuration directory containing `peers`, `routes`,
`areas`, and `schedules`:

```sh
cargo run -p tithd -- check-config /path/to/config
```

On Unix, run the current TSP-0012 local consumption service with path
presentation:

```sh
cargo run -p tithd -- serve-unix /var/run/tith.sock \
    /var/db/tith/state.redb /var/db/tith/exports tosser
```

This is an early, local-only interface. It authenticates clients using their
operating-system credentials and grants access only to the configured service
user.

To enable outbound `Submit`, `Submit-Items`, and `Lookup-Submission` on the
Unix endpoint, run the mailer form with its routing configuration, nodelist,
local identity, and matching signing key:

```sh
cargo run -p tithd -- serve-unix-mailer /var/run/tith.sock \
    /var/db/tith/state.redb /var/db/tith/exports mailer \
    /usr/local/etc/tith fidonet /var/db/tith/nodelist.txt \
    fidonet#1:123/45 /secure/path/node.secret
```

Submission ingests path Sources into immutable Job contents before returning
`New`. The current service deliberately omits the optional Move, Delete,
Truncate, and native-handle features from `Capabilities`.

For programs which use atomic filesystem rendezvous instead of sockets, one
configured principal can be served from an endpoint root containing
`requests`, `claimed`, `results`, and `acknowledgements`:

```sh
cargo run -p tithd -- serve-files /var/run/tith-files \
    /var/db/tith/state.redb /var/db/tith/exports tosser
```

Use `serve-files-mailer` with the same five trailing routing arguments shown
for `serve-unix-mailer` to enable the complete mailer operation set. Results
remain in `results/<token>.rsp` until the client durably publishes the empty
`acknowledgements/<token>.ack` file required by TSP-0008.

For authenticated loopback TCP, generate dedicated server and client IPC keys
and retain each printed public key in trusted configuration:

```sh
cargo run -p tithd -- generate-ipc-key /secure/path/server-ipc.secret
cargo run -p tithd -- generate-ipc-key /secure/path/client-ipc.secret
```

Then start the same consumption service over TSP-0009. The address must be an
IPv4 or IPv6 loopback address, and the two public-key arguments are the values
printed by the preceding commands:

```sh
cargo run -p tithd -- serve-tcp 127.0.0.1:24556 \
    /var/db/tith/state.redb /var/db/tith/exports tosser \
    SERVER-PUBLIC-KEY /secure/path/server-ipc.secret CLIENT-PUBLIC-KEY
```

The full mailer form adds the same submission configuration used by the Unix
binding:

```sh
cargo run -p tithd -- serve-tcp-mailer 127.0.0.1:24556 \
    /var/db/tith/state.redb /var/db/tith/exports mailer \
    SERVER-PUBLIC-KEY /secure/path/server-ipc.secret CLIENT-PUBLIC-KEY \
    /usr/local/etc/tith fidonet /var/db/tith/nodelist.txt \
    fidonet#1:123/45 /secure/path/node.secret
```

The authenticated TCP service and client also build on Windows. Platform ACLs
must protect both static secret-key files.

On Windows, the named-pipe service uses the TSP-0010 binary preambles and
authenticates the client through its impersonation token, process creation
time, logon identity, and session before reading an IPC document:

```powershell
cargo run -p tithd -- serve-named-pipe \\.\pipe\tith `
    C:\ProgramData\TITH\state.redb C:\ProgramData\TITH\exports tosser
```

`serve-named-pipe-mailer` adds the same routing and signing arguments as the
other mailer forms. Native handle tables are rejected and their optional
capabilities are not advertised; path presentation and path Sources work over
the pipe. The Windows CI job runs the named-pipe transaction test in addition
to the binding-independent workspace tests.

## The `tith` client binary

Client tools share one binary. Rust links its internal crates statically, so
each separate executable would re-embed the runtime and the shared protocol
crates; multiplexing keeps a single copy.

```sh
tith submit ...
tith nodelist convert ...
tith netmail scan ...
tith bso scan ...
tith inbound run ...
```

Install `tith-submit` as a link to `tith`. The file stem of `argv[0]` selects
the submit client directly, so `tith-submit submit request.ipc` and
`tith submit request.ipc` reach identical code, and the client named by
TSP-0006 section 9 keeps working unchanged:

```sh
ln -s tith /usr/local/bin/tith-submit
```

## Using `tith submit`

`tith submit` reads an exact canonical `Submit` or `Submit-Items` document,
sends one transaction, and writes only the complete IPC result to standard
output. It also constructs the standard query, lookup, control, and
capabilities requests. Select the configured carrier before the operation:

```sh
cargo run -p tith -- submit --unix /var/run/tith.sock capabilities
cargo run -p tith -- submit --files /var/run/tith-files query-job JOB-ID
cargo run -p tith -- submit --tcp 127.0.0.1:24556 \
    CLIENT-PUBLIC-KEY /secure/path/client-ipc.secret SERVER-PUBLIC-KEY \
    submit request.ipc
```

On Windows, supply the trusted service account SID from host configuration;
the client verifies the connected server process token before sending its
preamble or request:

```powershell
cargo run -p tith -- submit --named-pipe \\.\pipe\tith S-1-5-21-... `
    submit-items request.ipc
```

Use `-` as the submission filename to read standard input. The remaining
operations are `query`, `query-job`, `lookup`, `cancel`, `retry`, `reroute`,
and `capabilities`. For submission commands, exit status 0 means the
submission committed, 1 means a complete operation rejection or envelope-level
`Error` was written, and 2 means the transaction, result validation, or local
client failed.

The `tith-submit` library exposes the same binding clients plus one shared
`check_capabilities` conformance check. The daemon tests run that identical
check end-to-end through atomic files, Unix sockets, authenticated TCP, and,
in Windows CI, named pipes.

## Using `tith nodelist convert`

`tith nodelist convert` reads an FTS-5000.005 nodelist on standard input and
writes the TTS-5000 form on standard output. It substitutes spaces for
underscores in the name, location, and sysop fields, replaces `-Unpublished-`
with the empty phone number, drops the DCE speed field, and sorts each flag
into the TTS-5000 field that section 5.2 assigns it. Diagnostics go to
standard error.

```sh
cargo run -p tith -- nodelist convert --verify fidonet \
    < fidonet.230 > fidonet-nodelist.230
```

`--verify DOMAIN` parses the generated output back through `tith-nodelist`
before writing it, so the converter demonstrates that its result is a nodelist
the native parser accepts. Optional trailing arguments name override files,
each a `zone:net/node` line followed by `NN`, `LO`, `SN`, or `FL` directives
that replace the node name, location, or sysop name, or append flags.

The input must be the 7-bit ASCII that FTS-5000.005 specifies; a byte outside
that range is refused with its line number rather than decoded by guess.

## Using `tith netmail scan`

`tith netmail scan` reads a legacy netmail directory, converts each `###.msg`
according to TSP-0003, and submits it with its attached files through TSP-0006.
It selects files whose stem is all digits and whose extension is `msg` in any
case, and processes them in numeric order.

```sh
tith netmail scan --files /var/run/tith-files --origin fidonet#1:2/3 /var/spool/netmail
```

The legacy `DateTime` is local time. A `TZUTC` or `TZUTCINFO` control supplies
its offset from UTC; otherwise `--source-offset SECONDS` must give the trusted
offset for this source, in seconds east of UTC. A message without either is
left in place because its native timestamp would be ambiguous.

Two legacy conventions state what happens to an attached file after it is sent,
and they cannot be told apart from the bytes, so the convention is selected
rather than guessed:

- by default, FSC-0053.002 `FLAGS KFS` or `TFS`, which apply to **every**
  attachment of the message;
- with `--binkley`, the FTS-5005.003 directive prefixed to each Subject
  FileSpec — `#` truncate, `^` or `-` delete, `~` or `!` skip, `@` keep — which
  applies **per file**.

The same Subject reads differently under each. `^work.zip` is a delete
directive on `work.zip` with `--binkley`, and a file literally named
`^work.zip` without it.

A disposition other than keep needs the service to advertise `Submit.Delete` or
`Submit.Truncate`. When it does not, that message fails with a diagnostic
naming the missing feature and the scan continues; TSP-0013 does not permit
quietly dropping the cleanup the sender asked for.

After a Committed result the message is marked Sent, or deleted when it carries
K/S. `--kill-sent` deletes every committed message. K/S is about the message
itself; `KFS` and `TFS` are about its attachments. Anything short of Committed
leaves the `.msg` exactly as it was.

Runs are safe to overlap. A message is claimed by an atomic rename before it is
read, so exactly one scanner processes it, and the Sent bit stops a later run
resubmitting it. A claim left by an interrupted run is picked up once it is
older than `--recover-after` seconds (600 by default), following the same
age-based rule FTS-5005.003 uses for bsy files. Resubmission is harmless
because the Idempotency-Key is the message's FTS-0009.001 MSGID, so TSP-0006
returns `Existing` without repeating any work. A message with no MSGID gets a
generated key and is reported, since an interrupted run could send it twice.

`--dry-run` prints the requests that would be sent and takes no claim and no
write.

To exercise native TTS-0006 receipt, generate a dedicated node signing key and
place its printed public key in the applicable nodelist IIH entry or unlisted
Peer configuration:

```sh
cargo run -p tithd -- generate-node-key /secure/path/node.secret
```

`serve-mail` loads the normal four-file configuration set and one TTS-5000
domain nodelist. `LOCAL-IDENTITY` is a listed canonical address or an unlisted
Peer reference such as `@point`:

```sh
cargo run -p tithd -- serve-mail 0.0.0.0:24555 \
    /var/db/tith/state.redb tosser /usr/local/etc/tith \
    fidonet /var/db/tith/nodelist.txt fidonet#1:123/45 \
    /secure/path/node.secret
```

A planned key rotation may retain one or more predecessor secrets solely for
continuity replies:

```sh
    --retired-node-secret /secure/path/previous-node.secret
```

When a listed reply fails against the currently trusted key, the outbound
driver makes one dedicated `PublicKeyRequest`. A predecessor-signed response
can advance the service-owned durable pin and the original exchange is retried
once in the same schedule activation. This proves continuity, not revocation.
For a listed contact with no nodelist key or existing pin, a `Peer` may opt in
to first-contact pinning by combining a configured `Endpoint` with the
`Trust-On-First-Use` directive. That trust decision is never enabled by
default.

It both receives and sends. Local Messages, standalone Files, and FileRequests
are durably stored before `Accepted` is sent, and signed-item duplicates receive
`Accepted` without creating another inbound item. A NetMail for another node is
relayed rather than stored; a peer-addressed File or a FileRequest never is,
because neither carries a Destination a receiver could route on. EchoMail and
area Files are accepted only from configured `Receive-From` peers.

### Relay

A NetMail whose ultimate Destination is not this node is relayed: routed,
spooled, and sent onward by the same driver that carries locally submitted
mail. It never becomes an inbound item, so a hub transits mail with no
application running and nothing to claim it.

Relay is denied by default. TSP-0002 section 6 examines `Allow-Relay` and
`Deny-Relay` together in file order and the first rule whose three selectors all
match decides, so a `Deny-Relay` ahead of a matching `Allow-Relay` denies. With
no rule at all nothing matches and relay is refused, which means a leaf node
needs no configuration to stay a leaf:

```text
Routes fidonet#1:123/45
    Allow-Relay From Peer @downlink Origin All Destination Branch Zone fidonet#1
End
```

`From` selects the authenticated immediate peer, `Origin` the message's
effective signer — its Origin when that address has an applicable key and its
SignedOrigin otherwise — and `Destination` the ultimate Destination.

Only an `Origin-Valid` or `SignedOrigin-Valid` item is relayed. Anything else is
refused with rejection reason 2, so an item that cannot be authenticated end to
end is never passed on as though it could. A denial, an unroutable destination,
and a routing loop are each refused with reason 1. Every refusal is logged
locally and answered to the peer, which keeps responsibility with the sender so
the origin can dead-letter and notify its user.

Loop detection compares the selected next hop against every Via the message
carries, including the `PublicKey` of an unlisted one, and refuses rather than
falling through to a later method that would conceal it.

Only the routing suffix is rebuilt. The signed region is carried through byte
for byte and one Via naming this node is appended, so the end-to-end signature
still validates at the far end. Retransmission of an item already relayed is
answered `Accepted` without spooling a second copy, keyed on the signed-item
identity that TTS-0005 section 7 defines. Relayed jobs are committed under the
reserved application name `tithd-relay`, so no IPC client can collide with them.

### Outbound delivery

Submission commits a delivery copy per next hop into the spool; the schedules
file decides when those copies move. Each `Schedule` block is activated at its
`Start`, runs for its `Duration`, and repeats `Repeat-After` later. A Duration
of zero makes one pass over the work its Origin, Class, and Next-Hop lines
select and ends; a nonzero one stays open and picks up work that appears during
the interval. Missed activations coalesce to the most recent, and a schedule
never has two activations at once.

One connection carries the copies TSP-0002 section 9 calls compatible: the same
local AKA and the same exact next-hop identity, including the `PublicKey` when
that identity is unlisted. Copies for different local AKAs are never combined.
Endpoints come from the next hop's configured `Endpoint` lines in file order,
falling back to the usable TITH endpoints in its nodelist entry.

Responses are applied per TSP-0002 section 6. Rejected reason 1 from an
intermediate next hop fails as Relay-Denied, while the same response from the
ultimate Destination fails as Rejected. Reason 2 fails as Authentication;
reason 3 completes a conditional request and is not a failure; reason 4 retries
no earlier than its Timestamp, or at the next activation of the schedule when
it carries none. A request with no complete response stays eligible and does
not invoke permanent failure policy, which is also what happens to every copy
in a connection that fails outright. Copies left claimed by a killed daemon
are returned to the queue at startup.

### Poll

A `Poll <peer>` line contacts that Peer at every activation even when nothing is
queued for it, sending one `PollMessages`, one `PollFiles`, and one
`PollFileRequests`. Values the peer returns are stored by the same path an
incoming connection uses — the same authorization, the same duplicate handling —
and answered in the final Reply Bundle.

Inbound Poll is answered the same way in reverse. The snapshot is claimed
atomically: every held value matching the authenticated Bundle Origin, or none,
never part of the set. A value committed after that claim waits for a later
exchange. Held copies stay claimed until the peer's final Reply Bundle says what
became of them, so a connection that dies mid-transfer loses nothing. An inbound
Poll is not constrained by schedules, delivery class, passive status, or a retry
Timestamp. `PollMessages` returns held NetMail and EchoMail, `PollFiles` returns
both held distribution Files and held peer-addressed Files, and
`PollFileRequests` returns held FileRequests.

Three options tune the outbound half:

| Option | Effect |
| --- | --- |
| `--listen-only` | Never connect out and never poll. |
| `--local-offset SECONDS` | Seconds east of UTC, required by a schedule using `Start Local`. |
| `--timeout SECONDS` | Connect and read timeout for one outbound connection, 60 by default. |

`--local-offset` is required rather than detected because safe portable Rust
cannot read the host's civil offset, and silently treating local time as UTC
would move every schedule.

The original C proof of concept is retained for historical reference and can
still be built with:

```sh
gmake -C poc
```

## Using `tith bso scan`

`tith bso scan` reads an FTS-5005 Binkley Style Outbound, unpacks each queued
packet into native messages, and submits them through TSP-0006 with the files
their reference file carries.

```sh
tith bso scan --files /var/run/tith-files --origin fidonet#1:104/36 \
    --outbound /sbbs/fido/outbound
```

Packet message timestamps use `TZUTC`, `TZUTCINFO`, or the same trusted
`--source-offset SECONDS` fallback described for `tith netmail scan`.

It searches the outbound root, every `<root>.<zzz>` zone directory, and each
`*.pnt` subdirectory beneath them, accepting upper and lower case throughout.
For the default zone both the bare root and its zone-suffixed form are checked,
as FTS-5005 section 2 recommends. `--domain-root NAME=PATH` gives a domain its
own root, covering the BinkIT `outboundMap` extension. `--zone` and `--domain`
state which zone the bare root belongs to and which mapped root to prefer.

`--binkley` reads a Subject FileSpec under the FTS-5005 convention, where a
leading `#`, `^`, `-`, `~`, `!`, or `@` is a directive rather than part of the
name. Without it the FSC-0053.002 FLAGS reading applies and the whole Subject
word is the filename. The two are never inferred from the bytes because the
same Subject means different things under each. Either way the reference
file's own directive is what becomes the `Source-Disposition`, since that is
what a mailer would have acted on.

Flow files are processed in the section 3.2 order — Immediate, Continuous,
Direct, Normal — under the node's `.bsy`, which is created with an exclusive
create so two scanners cannot both hold it. Hold flavoured files are left alone
because Hold means wait for the remote to poll; `--include-hold` overrides that.
A `.hld` naming a future expiry skips the node, and one that has expired is
deleted per section 5.3.

### What it correlates

A file attach in FTN is already a NetMail, so the packet supplies the message
and the reference file supplies the payload and its post-send directive. Each
reference entry becomes one of:

- an `Attachment` on the message whose Subject FileList names it, carrying the
  reference file's directive as a `Source-Disposition`;
- reported as a TIC area distribution, when a `.tic` accompanies it;
- a TSP-0006 `Job Peer-File` otherwise, an ARCmail bundle being the usual case.
  TSP-0003 section 9 maps an entry no message claims and no TIC accompanies to a
  peer-addressed standalone File, addressed to the node whose outbound directory
  it sits in.

A `.req` request list is read too. TSP-0003 section 8 turns every parsed action
into one `Job FileRequest`, with a `+time` becoming `Newer-Than`. An action with
no exact TITH representation — a minus time is the documented case — is reported
and written back, so the file is rewritten rather than deleted.

Both need `--domain`: FTS-5005 has nowhere to record one, and a TTS-0004
Destination cannot be built without it. Without `--domain` these entries are
reported and left in place rather than addressed by guesswork. Under the Hold
flavour each Job carries `Next-Hop Passive`, so "wait for their poll" survives
the conversion.

### What it changes

Consuming an outbound is not read-only, which is why section 5.1 makes `.bsy`
required. After a Committed result the packet is deleted and the reference file
is rewritten without the consumed lines, or deleted when nothing is left.
Anything short of Committed leaves every byte alone.

The scanner never deletes or truncates the files a reference names. That
directive travels as a TSP-0006 `Source-Disposition` and the service performs
it after confirmed delivery, which is the only point at which it is correct.

## Using `tith inbound`

`tith inbound run` is the other half of `tith bso scan`. It claims TSP-0012
inbound items, converts them under TSP-0003, and publishes the legacy objects a
tosser polls for. It is the TSP-0013 section 4 adapter, so it keeps a private
durable ledger and only acknowledges an item once every object it published is
durable.

```sh
tith inbound run --files /var/run/tith-files --config /usr/local/etc/tith/adapter
```

Its configuration reuses the TSP-0002 section 2 grammar rather than inventing a
second one:

```text
Inbound /sbbs/fido/inbound
Ledger  /var/db/tith/adapter.redb
Domain  fidonet

Link uplink
    Peer     fidonet#1:104/1
    Local    fidonet#1:104/36
    Password secret
End

Area SYNCHRONET
    Tag SYNCHRONET
End

Orphan-Notice NetMail Sysop

Policy
    Unsigned              Deliver-Warn
    SignedOrigin-Invalid  Orphan
    Blocked-On-Standard   Defer
End
```

`Link` supplies the packet endpoints and password TSP-0003 section 6 requires
come from trusted link configuration, keyed by the `Peer` a claim reports.
`Area` maps each native `AreaName` to one unique legacy tag; a collision is
refused rather than resolved. `Policy` is the TSP-0011 section 5.1 final
authentication policy, whose defaults are the ones that document names.
`Orphan-Notice` defaults to `NetMail Sysop`; `Disabled` suppresses that local
administrative message, and all fields after `NetMail` form the legacy user
name.

### What it publishes

| Item | Objects, in publication order |
|---|---|
| Message | each attached File, then the `.pkt` naming them |
| distribution File | the companion, its `.tic`, then a diagnostic `.pkt` under `Deliver-Warn` |
| peer-addressed File | the file alone, then a diagnostic `.pkt` under `Deliver-Warn`; it has no TIC |
| FileRequest | nothing; it is answered, not published. See below |

Publication follows TSP-0013 section 5: each object is built under a private
`.tith-staging-` name, made durable, then given its final name by an exclusive
create which never replaces an existing file. Companions are published before
the object that names them, so a tosser can never see a packet whose companion
is missing. A name already in use is reported, not overwritten.

There is no lock file. FTS-5005 defines none for an inbound — it is entirely an
outbound spec — and SBBSecho's `import_packets` takes no lock either, so the
atomic publish is what makes the handoff safe.

### Carrying the signature

A published Message keeps its `TITHSIG` controls only when the adapter can apply
the TSP-0003 section 3.1 inverse conversion to the object it is about to publish
and get the original signed bytes back exactly. Otherwise the object goes out as
compatibility output without them, and the reason is recorded in the ledger.

That self-check is why absent and zero are one native fact. Every legacy format
carries the AttributeWord in a fixed header field and canonical output always
emits `TZUTC`, so an absent `LegacyAttributes` or `TimestampOffset` and a zero
one have the same legacy encoding, and only one of the two can be reconstructed.
TTS-0005 makes absence the one that survives, and likewise keeps attachment
presence in the `File` children rather than in AttributeWord bit 4. Without
those rules a Message originated through `tith submit` — which carries none of
them — could never be exported canonically, which is the case `TITHSIG` most
needs to serve.

`MessageText` works the same way and for the same reason. FTS-0001.016 makes a
hard carriage return the *end* of a paragraph, so TTS-0005 makes U+000A the end
of a native one: the text is empty or ends in U+000A, U+000D never appears, and
each terminator maps to one 0x0D and back with nothing invented or dropped at
the boundary. `tith submit` callers need not know that — TSP-0006 has the
service supply a missing final U+000A — but two native texts differing only in a
trailing newline would otherwise share one legacy encoding, and only one of them
could come back.

### Orphan recovery

An `Orphan` policy result publishes none of the affected item's legacy recovery
objects. Instead the ledger retains the exact native item TLV, its
authentication result and reason, and any legacy objects the adapter could
generate for deliberate recovery. By default the only adjacent object is a
private terminal NetMail to `Sysop` identifying the item and carrying the exact
authentication diagnostic; `Orphan-Notice Disabled` suppresses it. A pending
notice and its generated name are durable, so interrupted publication retries
without replacing another file.

The item remains quarantined after export; exporting is inspection and
recovery, not permission to feed an invalid item to the tosser automatically.

```sh
tith inbound orphan list --config /usr/local/etc/tith/adapter
tith inbound orphan export --config /usr/local/etc/tith/adapter \
    INBOUND-ID /var/tmp/orphan-recovery
```

The export directory must not exist. It receives `payload.tlv`, `reason.txt`,
and the generated objects beneath `legacy/`. Existing paths are never replaced.

### Batching

`--batch-window` and `--batch-max` bound how many items one packet may carry.
Both TSP-0012 section 10 and TSP-0013 section 5 endorse placing several
`InboundID` values in one legacy packet. Appending to an *already published*
packet is a different thing and is not done: section 5 forbids replacing a
published object, and SBBSecho opens and deletes packets with no lock at all.

The window must stay well inside the service's claim expiry, since every item in
a batch is held under its claim until the whole batch is published.

### Distribution

Native area fan-out is configured in the TSP-0002 `Areas` file. Each local
identity has `EchoArea` and `FileArea` blocks whose `Receive-From` lines
authorize inbound links and whose `Send-To` lines name every outbound link;
an optional `Class` on `Send-To` selects that copy's delivery class. The two
directions are deliberately separate. For example:

```text
Areas fidonet#1:123/45
EchoArea FSX_GEN
Receive-From @upstream
Send-To @upstream
Send-To @downstream Class Normal
End
End
```

For locally originated `Job EchoMail` and area `Job File` submissions, the
service creates one direct delivery copy for every applicable `Send-To`. For a
received distribution item, TSP-0006 `Job Forward` applies the same links after
excluding the immediate peer and identities already present in `SeenBy`.
Endpoint availability determines whether each copy is active or held for that
peer's poll; NetMail routing is never applied to an area copy.

An `Origin-Valid` or `SignedOrigin-Valid` `EchoMail` or file distribution item
arrives owing onward copies. The adapter always commits a TSP-0006 `Job Forward`
while the claim is still current. A Forward Job "MUST NOT decode and re-encode,
alter, or re-sign any covered byte", so the item's Signature and authentication
state survive the fan-out exactly.

The legacy object published beside it is terminal local delivery. **Configure
the tosser's areas as local-only**; allowing the tosser to forward would create
duplicate copies through a legacy round trip. If TITHSIG is stripped during
that round trip, later import cannot distinguish the message from originally
unsigned legacy input and creates a new gateway attestation instead of
preserving the earlier authentication state.

TSP-0006 section 6 refuses a Forward Job for an Unsigned, `Origin-Invalid`, or
`SignedOrigin-Invalid` item — those are final-delivery work with no native
onward copy. Their legacy delivery is terminal too, and the Deliver-Warn
diagnostic is adequate marking rather than a laundering vector.

### File requests

A claimed `FileRequest` is answered rather than published. `Request-Processor`
names an FSC-0086.001 external processor: the adapter writes the SRIF and request
list, runs it, and reads the `ResponseList`. Each offered file becomes one
TSP-0006 `Job Peer-File` addressed back to the requesting peer, which is the
shape TTS-0005 gives a File belonging to no distribution area. The whole set is
one Batch keyed on `InboundID`, so a redelivered request resolves to the original
Jobs instead of sending everything twice, and it is submitted while the claim is
still current.

The response markers map to what TSP-0006 can actually promise. `=` becomes
`Source-Disposition Delete`, which TSP-0005 section 5 performs only after every
delivery copy is Delivered. `+` becomes `Keep`. `-` asks for erasure whatever
happens, which has no native disposition, so it stays `Keep` and the adapter
removes the file itself.

That removal is an obligation, not a side effect, so it is recorded in the
ledger before the submission which makes it owed and cleared only once every
path is gone — TSP-0013 section 3 requires the adapter record its own later
legacy cleanup rather than remember it. `recover()` finishes whatever an
interrupted run left, and a removal which fails stays owed for the next one.
"In any case" is also not conditional on the file being sent: a `-` file the
request's `Newer-Than` condition excludes from the reply is still one the
processor asked to be rid of.

TTS-0005 section 6 permits an accepted `FileRequest` to return no files, and a
peer with no usable endpoint collects its answer by polling, so nothing here
depends on the requester still being connected. With no `Request-Processor`
configured the node will never serve a request, so it is rejected rather than
deferred forever.

## Repository layout

- [`standards/`](standards/) contains the versioned normative and supporting
  documents.
- [`crates/`](crates/) contains the Rust reference implementation.
- [`site/`](site/) builds the standards archive deployed by GitHub Pages.
- [`poc/`](poc/) contains the original C experiment for historical reference.

## Contributing

Protocol changes should make wire behavior more precise. If two independent
implementations could reasonably interpret a document differently, please
[open an issue](https://github.com/RealDeuce/tith/issues/new) so the standard
can be clarified instead of teaching the reference implementation to guess.

## License

The source code is available under the [ISC License](LICENSE). Each TITH
standard is released to the public domain unless it states otherwise.
