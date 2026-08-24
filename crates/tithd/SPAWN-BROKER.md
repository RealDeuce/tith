# `tithd` Spawn Broker Design

Status: implementation design, not a protocol specification.

TSP-0019 defines the proposed spawned-process IPC binding. This document
describes how the reference `tithd` can implement that binding without leaking
the daemon's already-open resources into a worker. If this design and the TSP
disagree, the TSP governs the carrier and this document must be corrected.

## Decision

`tithd` starts one sterile spawn-broker process before it opens its database,
node keys, listeners, export directories, or other long-lived resources, and
before it creates any thread. The broker remains the parent of every spawned
IPC worker and is the only process which creates one after daemon
initialization.

The broker runs as the same operating-system account as `tithd`. It does not
change user ID, create an access token, enter a sandbox, or apply a capability
profile. The configured executable is a trusted local extension operating with
the authority already granted to the `tithd` account.

The security property sought here is narrower and useful on its own: a worker
does not accidentally inherit an open database, secret key, listener,
connection, directory, export, or broker channel. This is a descriptor and
lifetime boundary, not protection from malicious code running as the same
account. Such code may be able to reopen paths which that account can access.

## Process and stream ownership

```text
                         private control channel
  main tithd  -------------------------------------------->  spawn broker
      |                                                         |
      | creates two pipe pairs                                  | spawns/reaps
      | keeps service ends                                      v
      +<===== result bytes on child's stdin ==============  IPC worker
      +====== request bytes on child's stdout ============>
```

For each activation, the main daemon creates two unidirectional pipes:

- a request pipe whose write end becomes the worker's standard output and
  whose read end remains in the daemon; and
- a result pipe whose read end becomes the worker's standard input and whose
  write end remains in the daemon.

Every end is noninheritable in the daemon from the instant it is created. The
broker's transferred copies become inheritable only as part of the exact
worker launch which names them.

The daemon sends only the two child ends, and an optional configured standard
error end, to the broker with a complete launch request. The broker maps them
to the new process's standard streams. After a successful spawn, the daemon
and broker close every redundant copy. The broker owns the native child
process object and reaps it; the daemon owns the TSP-0019 session streams.

The carrier direction is intentionally unusual but matches TSP-0019: requests
come from child standard output, while results go to child standard input.
Worker logs go to standard error. No diagnostic byte is recoverable if it is
written to standard output because it is then malformed IPC input.

## Startup sequence

The integrated service starts in this order:

1. Parse enough command-line state to identify service mode and the current
   executable.
2. Create one private daemon-to-broker control channel with all unintended
   ends noninheritable.
3. Start the same `tithd` executable in an internal broker mode. The private
   inherited channel selects that mode; invoking the internal argument without
   a valid channel fails immediately.
4. In the single-threaded broker, move the control channel to an owned handle,
   make it noninheritable by workers, close every unexpected inherited handle,
   and return `Ready`.
5. Only after `Ready`, load keys and configuration, open the store, bind
   listeners, create exports, and start threads.

The broker must never be restarted from the initialized, multithreaded daemon.
If it dies, `tithd` stops accepting new work, performs an orderly shutdown,
and exits so its service supervisor can restart the complete process pair.

This ordering is the backstop for resources opened by dependencies or host
startup code whose inheritance state is not under the daemon's direct control.
Normal daemon resources must still be created noninheritable or close-on-exec
atomically wherever the host offers that operation.

## Internal broker protocol

The broker channel is a private implementation protocol, not TSP-0004 text and
not a public extension point. It uses bounded, length-framed binary records
because its peer is the trusted daemon. Bounds are local resource policy, not
protocol limits imposed on TITH data.

A launch request contains the complete invocation:

- an ephemeral correlation ID;
- an absolute executable path;
- the argument vector as separate strings;
- an explicit environment or an explicit list of inherited environment names;
- an optional working directory;
- the received child standard-input and standard-output handles;
- the standard-error policy; and
- configured process resource and termination policy.

There is no registry of predefined launch IDs. The correlation ID only matches
asynchronous broker replies to this request and conveys no authority. The main
daemon has already selected and authorized the executable, principal,
Applications, operations, and activation condition. The broker validates
record framing and native-handle consistency, then performs that exact launch.
It never invokes a shell and never interprets remote or IPC data as an argument
vector.

The broker replies with either `Spawned` or a complete launch failure. It later
reports `Exited` for observation and resource cleanup. Neither reply is an IPC
operation result, and the daemon must not use it to acknowledge an inbound
item, commit a Job, or acknowledge an event.

## Unix implementation

The initial control channel is a private Unix-domain socket pair. The daemon
passes child pipe ends with `SCM_RIGHTS`. Received descriptors are marked
close-on-exec immediately; an API which supplies the flag atomically on receipt
is preferred where available.

The broker gives the received owned descriptors to
`std::process::Command` as the child's `Stdio`. The standard library performs
the final standard-descriptor mapping. Host calls for socket descriptor
transfer and enumeration belong behind a safe Unix binding so the crate does
not add an `unsafe` Unix module.

Before accepting launch requests, the broker closes every descriptor other
than its standard diagnostics and control channel. The implementation must not
assume that scanning and changing the initialized daemon's descriptor table is
safe; only the sterile, single-threaded broker performs that cleanup.

## Windows implementation

The initial control channel is an anonymous pipe or private named pipe created
only for this daemon and broker. The daemon duplicates each child pipe handle
into the broker process and sends the resulting broker-local value in the
private launch record.

The initial broker launch also uses an explicit handle list containing only
the broker control channel and configured standard diagnostics. It therefore
does not depend on inspecting or repairing an ambient Windows handle table.

The broker uses `CreateProcessW` with `STARTUPINFOEXW` and an explicit
`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. That list contains only the worker's
standard input, standard output, and configured standard error. The broker
must not rely on the ambient inheritable-handle set. It retains the returned
process handle until completion, closes the thread handle promptly, and closes
its copies of the standard-stream handles after the process is created.

These raw Win32 calls live in the existing audited Windows host-binding module
or a sibling Windows-only host module. Launch selection, record validation,
session processing, and activation remain safe portable Rust.

## Worker session

The daemon assigns the configured IPC principal to the launch before any
request is read. It runs the same `IpcService` dispatcher used by other local
bindings, with that principal fixed for the life of the child. The binding
loop:

1. reads one complete TSP-0004 request from the worker's standard output;
2. dispatches it against the shared authoritative store;
3. writes and flushes one complete result to the worker's standard input; and
4. repeats until clean inter-transaction end of file or an error.

Only one transaction is outstanding. The parser must frame the outer document
itself rather than waiting for pipe closure. A worker can therefore claim an
item, submit resulting work, acknowledge the claim, and request another item
without another process launch.

TSP-0019 revision 1 has no associated native-handle tables. Workers use
`Source-Path` for submission and `Presentation Path` for inbound items. The
standard streams are carrier handles and cannot double as request- or
result-associated payload handles. Adding such a courier requires a later TSP
revision and a corresponding broker design update.

The worker-side binding must mark its standard input and standard output
noninheritable before it launches any descendant. Keeping either stream open
in a descendant would extend both the IPC identity and session lifetime.

## Activation

Activation is configuration and scheduler policy, not an IPC operation. A
configuration entry associates:

- an activation condition, such as eligible work for an Application or a due
  schedule for a configured callout driver;
- the IPC principal and allowed Applications and operations;
- the complete executable invocation; and
- local concurrency, retry, diagnostic, timeout, and termination policy.

The first implementation should coalesce repeated notifications while one
worker for an entry is active. The worker drains eligible work with `Now`
operations and exits after `Empty`. Coalescing is an efficiency decision only:
claims, submission keys, and durable operation results remain the correctness
mechanisms, and another activation after a race is harmless.

Startup recovery evaluates every configured condition after the store is open.
A commit which creates eligible work schedules activation only after that
commit is durable. A worker exit, timeout, or signal never resolves the work;
the store state makes it eligible for a later activation under the ordinary
retry policy.

### Scheduled callout drivers

The same activation path can eventually launch a short-lived legacy callout
driver—for example, one which handles a callout carrying FTS-0001.016
messages—without adding that protocol to the main daemon or requiring its
adapter to remain resident.
`tithd` owns the schedule, durable outbound state, retry policy, and IPC
principal. The child owns one invocation of the external protocol engine.

That use case depends on future TSP-0004 operations which define how the child
claims a callout assignment, obtains its data, and reports a durable outcome.
This broker design must not anticipate those messages by placing the peer,
Job, payload, or result in arguments, environment variables, exit status, or
broker records. Until the operations exist, a scheduled launch can provide
activation but cannot itself assign or complete mail work.

## Failure and shutdown

- A launch failure leaves the activation eligible and applies local retry
  policy.
- End of file during a request commits nothing from that partial request.
- End of file during a result leaves the worker with an unknown outcome; the
  operation's lookup or idempotency rules provide recovery.
- Worker exit status and standard-error output are diagnostics only.
- Broker control-channel failure is fatal to the initialized daemon because a
  replacement broker could inherit the daemon's live resources.
- On daemon shutdown, the broker stops launching, closes unused transferred
  handles, allows configured graceful worker termination, then terminates and
  reaps workers which exceed that policy.
- On daemon disappearance, control-channel end of file triggers the same
  worker cleanup. Closing the IPC stream alone is not treated as proof that a
  worker has exited.

## Validation plan

The implementation is not complete until automated tests demonstrate at
least:

- a deliberately inheritable descriptor or handle present at broker startup
  is absent from a worker;
- database, key, directory, listener, accepted-connection, export, and broker
  control handles opened after `Ready` are absent from a worker;
- concurrent daemon opens cannot race a worker launch into inheriting a
  resource;
- the worker receives exactly its three configured standard streams;
- a descendant does not retain the worker's carrier streams;
- multiple sequential transactions frame correctly without pipe closure;
- diagnostic output on standard output fails as malformed IPC;
- partial requests and partial results follow TSP-0019 recovery rules;
- every native child is reaped after normal exit, launch failure, timeout,
  broker shutdown, and daemon disappearance;
- broker failure makes the initialized daemon exit rather than spawning a
  replacement; and
- Unix descriptor transfer and the Windows explicit handle list enforce the
  same observable inheritance boundary.

## Implementation sequence

1. Add the early internal broker mode, private control channel, descriptor
   cleanup, structured launch request, and process reaping on Unix and Windows.
2. Refactor service startup so one authoritative store and `IpcService` are
   shared by native mail, outbound delivery, existing IPC listeners, and the
   spawned binding.
3. Add the TSP-0019 sequential session loop with path-only capabilities.
4. Add configuration and durable-work activation, initially coalescing one
   active worker per configured entry.
5. Add end-to-end robot or request-processor coverage only after the carrier
   and failure tests pass on both host families.
