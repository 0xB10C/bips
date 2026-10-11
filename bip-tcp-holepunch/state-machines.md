# State tables for the TCP hole punching BIP draft (v0.3)

Each table lists (state, event, action, next state). Rule numbers refer
to the main document. Events not listed for a state are ignored, except
protocol errors, which close the connection they arrived on.

## Session (one per accepted `punch`, both parties)

Key: (local punch port, `peer`). Window = `WINDOW_MS` from session start.
For a recipient of `punch`, this is its receipt time. A Profile B advertiser
starts on acceptance of a validated `rendezvous` (R-12.5).

| State | Event | Action | Next |
|-------|-------|--------|------|
| (none) | `punch` received, R-5.1 fails (incl. answering `punch` whose `peer` != `rendezvous` target, or unsolicited `punch` without matching cap) | ignore; optionally close the connection | (none) |
| (none) | `punch` received, valid | reserve inbound slot (responder) or hole-punch outbound slot (initiator); start window timer; open punch-port socket; `connect(peer)` | PUNCHING |
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
| HAS_ADDRESS | Profile A: outbound to a `COORDINATOR` peer open with `ADVERTISED` + `PUNCHPORT` sent; Profile B: coordination onion service published | eligible to announce | READY |
| READY | announce timer (`ANNOUNCE_INTERVAL`) and free inbound slot | send `HOLEPUNCH` element (R-6.4 restricts Profile B to clearnet peers) | READY |
| READY | no free inbound slot, or external address dropped, or (A) coordinator connection closed | stop announcing | HAS_ADDRESS / NOT_EIM |
| READY | (A) unsolicited `punch(responder)` from coordinator; (B) `rendezvous` on coordination endpoint valid per R-12.4 | (B) send `punch(initiator, peer=target)`, close the coordination connection; start Session(responder, peer=requester) | READY (+session) |
| READY | (B) `ONION_ROTATE_H` elapsed | new onion key; republish; announcements use the new address | READY |

## Connector

| State | Event | Action | Next |
|-------|-------|--------|------|
| IDLE | valid `HOLEPUNCH` element received | insert into cache (caps, TTL) | IDLE |
| IDLE | free hole-punch outbound slot, `HP_ATTEMPT_INTERVAL` elapsed, eligible cache entry (R-7.1) | remove entry; Profile A: use the existing connection to the coordinator if any, else open one from punch port with `PUNCHPORT`; Profile B: Tor (stream isolation) to onion | COORDINATING |
| COORDINATING | feature exchange complete (immediate on an existing connection) | send `rendezvous(target, own external address)`; start `COORD_TIMEOUT_MS` | WAITING |
| WAITING | `punch(initiator, peer)` with `peer == target` and R-5.1 passes | start Session(initiator) | IN_SESSION |
| WAITING | `punch` with `peer != target` or role responder | ignore (R-5.1); keep waiting | WAITING |
| WAITING | timeout or disconnect | close a connection opened only for coordination | IDLE |
| IN_SESSION | session CONNECTED or FAILED | close a connection opened only for coordination | IDLE |

## Coordinator (Profile A)

Per inbound peer with `PUNCHPORT`: remember the observed endpoint, the
caps, whether `rendezvous`/`punch` was already used on the connection, and the
current session partner if any.

| State | Event | Action | Next |
|-------|-------|--------|------|
| IDLE | `rendezvous(target, requester)` from B | find inbound A with `ADVERTISED` + `PUNCHPORT` and observed == target; check B set `PUNCHPORT` and requester == obs(B), neither A nor B within `WINDOW_MS + GRACE_MS` of a previous `punch`, A/B addresses differ, family match, per-target rate (R-11.2) | |
| IDLE | check failed | do nothing (B times out); optionally close B | IDLE |
| IDLE | check passed | send `punch(responder, obs(B))` to A then `punch(initiator, obs(A))` to B; mark both in session; start liveness timer `WINDOW_MS + GRACE_MS` | PAIRED |
| IDLE (pool) | two `POOL_OK` + `PUNCHPORT` peers available with different addresses, not paired within `PER_IP_INTERVAL` | roles by lexicographic endpoint order (R-11.8); send both `punch`; start liveness timer | PAIRED |
| IDLE (handoff) | inbound full, eviction rules select X; another inbound Y exists; both `HANDOFF_OK` + `PUNCHPORT`, past `verack`, distinct addresses, no elevated permissions | roles per R-11.8; send both `punch`; start liveness timer; defer eviction of X (capacity exceeded by one) | PAIRED |
| PAIRED | liveness timer fires | clear session marks; (handoff) disconnect X; connections may be closed | IDLE |
| any | peer disconnects | forget its observation; if in session, nothing else (the other party times out) | IDLE |

## Coordination connection

Profile A: B's connection to C (usually an existing outbound). Profile B:
inbound on A's coordination onion service.

| State | Event | Action | Next |
|-------|-------|--------|------|
| OPEN | message other than `version`, `verack`, `feature`, `ping`, `pong`, `rendezvous`, `punch` on a connection opened only for coordination | disconnect (R-7.4) | CLOSED |
| OPEN | `rendezvous` while one is outstanding on this connection | disconnect (R-4.4) | CLOSED |
| OPEN | `COORD_TIMEOUT_MS` without `punch` (B) / without handshake and `rendezvous` (A, Profile B) | disconnect | CLOSED |
| OPEN | Profile B: `punch` sent | A closes (R-12.5) | CLOSED |
| OPEN | Profile A: `WINDOW_MS + GRACE_MS` after `punch` | coordinator may close a coordination-only connection; an ordinary connection stays | OPEN / CLOSED |
