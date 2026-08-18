This repository contains the TITH protocol standards and the Rust reference
implementation. The original C experiment remains under `poc/` as historical
proof-of-concept code; new implementation work belongs in the Cargo workspace.

The generated standards archive is published at
<https://realdeuce.github.io/tith/>.

The reference implementation is split into focused crates rather than one
crate per standard:

- `tith-crypto`: the only unsafe and libhydrogen-facing crate;
- `tith-wire`: canonical integers, addresses, TLVs, Bundles, and items;
- `tith-nodelist`: TTS-5000 parsing and key lookup;
- `tith-exchange`: blocking TTS-0006 exchange state;
- `tith-config` and `tith-router`: TSP-0002 policy;
- `tith-store`: pure-Rust `redb` durable state;
- `tith-ipc`: canonical TSP-0004 and TSP-0012 documents; and
- `tithd`: the FreeBSD-first blocking service.

Build and test the workspace with:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Validate a four-file TSP-0002 configuration set whose directory contains
`peers`, `routes`, `areas`, and `schedules`:

```sh
cargo run -p tithd -- check-config /path/to/config
```

Run the current Unix-domain TSP-0012 consumption service with path
presentation:

```sh
cargo run -p tithd -- serve-unix /var/run/tith.sock \
    /var/db/tith/state.redb /var/db/tith/exports tosser
```

The socket authenticates the operating-system peer and currently authorizes
only the service user. Native network receipt and outbound submission remain
under construction; the daemon is not yet a production mailer.

Build the frozen proof of concept with `gmake -C poc`.

Goals:
- Simple to implement
- Easily extensible
- Use public key authentication
- Use readily available algoithms
- Always authenticate the server
- Allow anonymous sends (for new nodes)
- Allow replies to anonymous sends (for new nodes)
	- Require daily poll to keep "alive"
- Do not enforce any arbitrary limits
- No legacy baggage

Non-goals:
- Password authentication
- Abort/Resume
- Allowing multiple addresses on either end of a connection
- Optional behaviour (enecryption, authentication, etc)
- Compatibility

Good FTSC Documents:
FSC-0067 (MSGTO, ASSOC, SPTH, Address format)
FSC-0068 (Tiny SEEN-BYs, good analysis of echomail topology, good analysis of control paragraphs)
FSC-5000 (Nodelist format, accurately describes the format, format is bad)
FSC-5001 (Nodelist flags, good descriptions, secretly messed with by FTS-4010 though)
FTS-5005 (BSO outbound, can actually be implemented as described and if that's done, will actually work, 5D)
FSC-0057 (Conference Manager aka AreaFix Commands)

Bad FTSC Documents:
FTS-0001 (XModem over dial-up, not implementable over sockets)
FTS-4000 (Specifies basically nothing)
FTS-4008 ("Timezones are easy", Simple is to just specify local time in header, UTC time in kludge, nobody does that)
FTS-4010 (PING, TRACE, Just copies the bad spec from FTS-5000 below, secretly overrides part of FTS-5001)
FTS-5002 ("Heres five things, don't ever do four of them")
FTS-5003 (Probobly random bits copied from Wikipedia with random arbitrary limits tossed in)
FTS-5004 ("DNS Nodelist" that provides a single flag from the nodelist)

Maybe needed (but bad) FTSC Documents:
FTS-0004 (Tear line, origin line, "full" SEEN-BYs, 2D PATH, prefer FSC-0068)
FTS-0006 (REQ file format)
FTS-0009 (MSGID and REPLY, highly restrictive and requires wishful magic)
FTS-4001 (INTL, FMPT, TOPT, because we still can't put a 4D address anywhere)
FTS-4009 (Via, arbitrary stupid limits, timezone, allows random YOLO formats)
FTS-5000 (PING, TRACE, specification failure "clearly quoting" is basically the whole spec)
FTS-5006 (TIC format, DOS only, highly underspecified, examples seem to be normative?)
FSP-1040 (SRIF, Requires Baud "IP lies", requires a time limit, but no indication what to do with it, Typo, Fixed lists)
FSP-0046 (PID, TID, "No program can have a name over 10 characters", strong opinions on how I should version my software)
