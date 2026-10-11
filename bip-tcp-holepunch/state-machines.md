# State tables for the TCP hole punching BIP draft (v0.3)

Each table lists (state, event, action, next state). Rule numbers refer
to the main document. Events not listed for a state are ignored, except
protocol errors, which close the connection they arrived on. Connection
retention prevents planned eviction and coordination cleanup; protocol
violations, failed liveness checks, and stalled block/header downloads may
still close a retained connection (R-5.14).

## Session (one per accepted `punch` or Profile B `rendezvous`)

Key: (local punch port, `peer`). Window = `WINDOW_MS` from session start.
For a recipient of `punch`, this is its receipt time. A Profile B advertiser
starts on acceptance of a validated `rendezvous` (R-12.5).

| State | Event | Action | Next |
|-------|-------|--------|------|
| (none) | `punch` received, R-5.1 fails (incl. answering `punch` whose `peer` != `rendezvous` target, or unsolicited `punch` without matching cap) | ignore; optionally close the connection | (none) |
| (none) | valid `punch` received, or Profile B advertiser accepts a validated `rendezvous` | reserve inbound slot (responder) or hole-punch outbound slot (initiator); start window timer; open punch-port socket; `connect(peer)` | PUNCHING |
| PUNCHING | attempt fails (reset, unreachable, immediate error) | close socket; start `RETRY_MS` timer | WAITING_RETRY |
| PUNCHING | attempt fails because the 4-tuple is in use | close socket; do not retry; await a matching listener socket until the session deadline (R-5.6) | PUNCHING |
| WAITING_RETRY | retry timer fires, window not over | open punch-port socket; `connect(peer)` | PUNCHING |
| PUNCHING | `connect()` completes, remote endpoint == `peer` | session connection = this socket; initiator: send BIP 324 key; responder: wait | ESTABLISHED |
| PUNCHING / WAITING_RETRY | listener accepts socket with remote endpoint == `peer` | close pending attempt; session connection = accepted socket; initiator: send BIP 324 key; responder: wait | ESTABLISHED |
| PUNCHING / WAITING_RETRY | window timer fires | close pending attempt; start `GRACE_MS` timer | GRACE |
| GRACE | listener accepts socket with remote endpoint == `peer` | as above | ESTABLISHED |
| ESTABLISHED (responder) | BIP 324 bytes arrive | complete handshake as responder | HANDSHAKE |
| ESTABLISHED (responder) | v1 prefix arrives | close connection; release slot | FAILED |
| ESTABLISHED (initiator) | BIP 324 handshake completes | send `version` | HANDSHAKE |
| any non-terminal | `WINDOW_MS + GRACE_MS` after session start, without `verack` | close all session sockets; release slot | FAILED |
| HANDSHAKE | `verack` received | account per R-8.1 (initiator: hole-punch outbound, responder: inbound) | CONNECTED |
| HANDSHAKE | disconnect before `verack` | release slot | FAILED |
| any non-terminal | shutdown or punch port closed | close all; release slot | FAILED |

Terminal: CONNECTED, FAILED (I-6).

## Punch-port listener

| State | Event | Action | Next |
|-------|-------|--------|------|
| LISTENING | accept yields socket whose remote endpoint matches an active session's `peer` | hand to that session | LISTENING |
| LISTENING | accept yields socket matching no session | close (R-5.7, I-2) | LISTENING |

## Advertiser (per address family)

| State | Event | Action | Next |
|-------|-------|--------|------|
| NOT_EIM | exactly one endpoint has reports from at least two connected peers in distinct network groups | external address = that endpoint | HAS_ADDRESS |
| HAS_ADDRESS / READY | a second endpoint has reports from at least two connected peers in distinct network groups | drop external address; stop announcing (R-2.3) | NOT_EIM |
| HAS_ADDRESS / READY | fewer than two distinct network groups still report the external address | drop external address; stop announcing (R-2.2, R-2.4) | NOT_EIM |
| HAS_ADDRESS | Profile A: outbound to a `COORDINATOR` peer open with `ADVERTISED` + `PUNCHPORT` sent; Profile B: current non-retiring coordination onion service published and within its announcement lifetime | eligible to announce | READY |
| READY | announce timer (`ANNOUNCE_INTERVAL`) and free inbound slot | send `HOLEPUNCH` element (R-6.4 restricts Profile B to clearnet peers) | READY |
| READY | no free inbound slot, or external address dropped, or (A) coordinator connection closed | stop announcing | HAS_ADDRESS / NOT_EIM |
| READY | (A) unsolicited `punch(responder)` that passes R-5.1 | start Session(responder, peer=`punch.peer`) | READY (+session) |
| READY | (B) `rendezvous` on coordination endpoint valid per R-12.4 | start Session(responder, peer=requester); send `punch(initiator, peer=target)` and drain it to the socket by the original R-12.2 deadline before closing | READY (+session) |
| READY | (B) `ONION_ROTATE_H` elapsed since first announcement | stop announcing old identity; generate and publish new onion key; keep old endpoint reachable for `CACHE_TTL + 10 min` after its last announcement | HAS_ADDRESS |

## Connector

| State | Event | Action | Next |
|-------|-------|--------|------|
| IDLE | valid `HOLEPUNCH` element received | insert into cache (caps, TTL) | IDLE |
| IDLE | free hole-punch outbound slot, `HP_ATTEMPT_INTERVAL` elapsed, eligible cache entry (R-7.1) | remove entry; Profile A: reuse an outbound connection with `PUNCHPORT` sent, or open one from the punch port; Profile B: Tor (stream isolation) to onion | COORDINATING |
| COORDINATING | feature exchange complete; Profile A peer advertised `COORDINATOR` | send `rendezvous(target, own external address)`; start `COORD_TIMEOUT_MS` | WAITING |
| WAITING | `punch(initiator, peer)` with `peer == target` and R-5.1 passes | complete outstanding request; start Session(initiator); Profile A: set connection liveness deadline from receipt of this `punch` | IN_SESSION |
| WAITING | answering `punch` fails any R-5.1 check, including `peer != target` or role responder | ignore; optionally close the connection; if retained, keep the request outstanding and its original deadline unchanged (R-4.4) | WAITING / IDLE |
| WAITING | timeout or disconnect | close a connection opened only for coordination | IDLE |
| IN_SESSION | session CONNECTED or FAILED | Profile A: retain a connection opened only for coordination until the receipt-based liveness deadline in R-7.3; an existing ordinary connection stays open | IDLE |

## Coordinator (Profile A)

Per inbound peer with `PUNCHPORT`: remember the observed endpoint, the
caps, the time of the last `punch` sent on the connection, and the current
session partner if any. Repeated exchanges are permitted after the relevant
cooldown and rate limits expire.

| State | Event | Action | Next |
|-------|-------|--------|------|
| IDLE | `rendezvous(target, requester)` from B | find inbound A with `ADVERTISED` + `PUNCHPORT` and observed == target; check B set `PUNCHPORT` and requester == obs(B), neither A nor B within `WINDOW_MS + GRACE_MS` of a previous `punch`, A/B addresses differ, family match, per-target rate (R-11.2) | |
| IDLE | check failed | do nothing (B times out); optionally close B | IDLE |
| IDLE | check passed | send `punch(responder, obs(B))` to A then `punch(initiator, obs(A))` to B; record each send time; mark both in session; start liveness timer `WINDOW_MS + GRACE_MS` | PAIRED |
| IDLE (pool) | two `POOL_OK` + `PUNCHPORT` peers available with different addresses, not paired within `PER_IP_INTERVAL` | roles by lexicographic endpoint order (R-11.8); send both `punch`; record each send time; start liveness timer | PAIRED |
| IDLE (handoff) | no handoff pending; inbound full, eviction rules select X; another inbound Y exists; both `HANDOFF_OK` + `PUNCHPORT`, past `verack`, distinct addresses, no elevated permissions | roles per R-11.8; send both `punch`; record each send time; start liveness timer; defer eviction of X (capacity exceeded by one) | PAIRED |
| PAIRED | liveness timer fires | clear session marks; (handoff) disconnect X; connections may be closed | IDLE |
| any | peer disconnects | forget its observation; if in session, nothing else (the other party times out) | IDLE |

## Coordination connection

Profile A: B's connection to C (usually an existing outbound). Profile B:
inbound on A's coordination onion service.

| State | Event | Action | Next |
|-------|-------|--------|------|
| OPEN | message other than `version`, `verack`, `feature`, `ping`, `pong`, `rendezvous`, `punch` on a dedicated Profile B coordination connection | disconnect (R-7.4) | CLOSED |
| OPEN | local `rendezvous` already outstanding | do not send another request until an answer is accepted or the original deadline expires (R-4.4) | OPEN |
| OPEN | connector: response deadline measured from sending `rendezvous` expires without an accepted answering `punch`; advertiser, Profile B: R-12.2 deadline expires without handshake and `rendezvous` | close a connection opened only for coordination; an existing ordinary Profile A connection stays open | OPEN / CLOSED |
| OPEN | Profile B: valid `rendezvous` accepted | start responder session; queue `punch`; retain original R-12.2 deadline (R-12.5) | DRAINING |
| DRAINING | all transport bytes encoding `punch` written to socket | A closes coordination connection (R-12.5) | CLOSED |
| DRAINING | send fails or original R-12.2 deadline expires | close coordination connection; cancel associated session if still in progress, close its sockets and release its reserved slot | CLOSED |
| OPEN | Profile A: `WINDOW_MS + GRACE_MS` after sending `punch` (coordinator), or accepting the answering `punch` (connector) | a connection opened only for coordination may close; an existing ordinary connection stays | OPEN / CLOSED |
