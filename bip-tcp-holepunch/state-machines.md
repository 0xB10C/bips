# State tables for the TCP hole punching BIP draft (v0.2)

Each table lists (state, event, action, next state). Rule numbers refer
to the main document. Events not listed for a state are ignored, except
protocol errors, which close the connection they arrived on.

## Session (one per accepted `punch`, both parties)

Key: (local punch port, `peer`). Window = `WINDOW_MS` from receipt.

| State | Event | Action | Next |
|-------|-------|--------|------|
| (none) | `punch` received, R-5.1 fails | ignore; optionally close the connection | (none) |
| (none) | `punch` received, valid | reserve inbound slot (PR) or hole-punch outbound slot (PI); start window timer; open punch-port socket; `connect(peer)` | PUNCHING |
| PUNCHING | attempt fails (reset, unreachable, immediate error) | close socket; start `RETRY_MS` timer | WAITING_RETRY |
| WAITING_RETRY | retry timer fires, window not over | open punch-port socket; `connect(peer)` | PUNCHING |
| PUNCHING | `connect()` completes, remote endpoint == `peer` | session connection = this socket; PI: send BIP 324 key; PR: wait | ESTABLISHED |
| PUNCHING / WAITING_RETRY | listener accepts socket with remote endpoint == `peer` | close pending attempt; session connection = accepted socket; PI: send BIP 324 key; PR: wait | ESTABLISHED |
| PUNCHING / WAITING_RETRY | window timer fires | close pending attempt; start `GRACE_MS` timer | GRACE |
| GRACE | listener accepts socket with remote endpoint == `peer` | as above | ESTABLISHED |
| GRACE | grace timer fires | release slot | FAILED |
| ESTABLISHED (PR) | BIP 324 bytes arrive | complete handshake as responder | HANDSHAKE |
| ESTABLISHED (PR) | v1 prefix arrives | close connection; release slot | FAILED |
| ESTABLISHED (PI) | BIP 324 handshake completes | send `version` | HANDSHAKE |
| ESTABLISHED | window + grace elapsed without handshake progress | close; release slot | FAILED |
| HANDSHAKE | `verack` received | classify per R-8.x; connector applies R-7.4 | CONNECTED |
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
| NOT_EIM | two connected observers in distinct address groups report the same endpoint | candidate = that endpoint | HAS_CANDIDATE |
| HAS_CANDIDATE | two connected observers report different ports | drop candidate (R-2.3) | NOT_EIM |
| HAS_CANDIDATE | all observers reporting the candidate disconnected | drop candidate (R-2.4) | NOT_EIM |
| HAS_CANDIDATE | Profile A: outbound to a `COORDINATOR` peer open with `ADVERTISED` + `PUNCHPORT` sent; Profile B: coordination onion service published | eligible to announce | READY |
| READY | announce timer (`ANNOUNCE_INTERVAL`) and free inbound slot | send `HOLEPUNCH` element (R-6.4 restricts Profile B to clearnet peers) | READY |
| READY | no free inbound slot, or candidate dropped, or (A) coordinator connection closed | stop announcing | HAS_CANDIDATE / NOT_EIM |
| READY | (A) `punch(PR)` from coordinator; (B) `rendezvous` on coordination endpoint valid per R-12.4 | (B) send `punch(PI, requester)`; start Session(PR) | READY (+session) |
| READY | (B) `ONION_ROTATE_H` elapsed | new onion key; republish; announcements use the new address | READY |

## Connector

| State | Event | Action | Next |
|-------|-------|--------|------|
| IDLE | valid `HOLEPUNCH` element received | insert into cache (caps, TTL) | IDLE |
| IDLE | free hole-punch outbound slot, `HP_ATTEMPT_INTERVAL` elapsed, eligible cache entry (R-7.1), own candidate in target family | remove entry; Profile A: outbound to coordinator from punch port with `PUNCHPORT`; Profile B: Tor (stream isolation) to onion | COORDINATING |
| COORDINATING | feature exchange complete | send `rendezvous(target, own candidate)`; start `COORD_TIMEOUT_MS` | WAITING |
| WAITING | `punch(PI, peer)` valid | start Session(PI) | IN_SESSION |
| WAITING | timeout or disconnect | close coordination connection | IDLE |
| IN_SESSION | session CONNECTED | verify remote endpoint == announcement target (R-7.4) else close; close coordination connection | IDLE |
| IN_SESSION | session FAILED | close coordination connection | IDLE |

## Coordinator (Profile A)

Per connected peer with `PUNCHPORT`: remember the observed endpoint, the
caps, whether `rendezvous`/`punch` was already used on the connection, and the
current session partner if any.

| State | Event | Action | Next |
|-------|-------|--------|------|
| IDLE | `rendezvous(target, requester)` from B | find A with `ADVERTISED` + `PUNCHPORT` and observed == target; check A not in session, A/B addresses differ, family match, per-target rate (R-11.2), one `rendezvous` per connection (R-4.4) | |
| IDLE | check failed | do nothing (B times out); optionally close B | IDLE |
| IDLE | check passed | send `punch(PR, obs(B))` to A then `punch(PI, obs(A))` to B; mark both in session; start liveness timer `WINDOW_MS + GRACE_MS` | PAIRED |
| IDLE (pool) | two `POOL_OK` + `PUNCHPORT` peers available with different addresses, not paired within `PER_IP_INTERVAL` | roles by lexicographic endpoint order (R-11.8); send both `punch`; start liveness timer | PAIRED |
| IDLE (handoff) | inbound full, would evict X to admit Y; both `HANDOFF_OK` + `PUNCHPORT`, past `verack`, distinct addresses, no elevated permissions | roles per R-11.8; send both `punch`; start liveness timer; defer eviction of X | PAIRED |
| PAIRED | liveness timer fires | clear session marks; (handoff) disconnect X; connections may be closed | IDLE |
| any | peer disconnects | forget its observation; if in session, nothing else (the other party times out) | IDLE |

## Coordination connection

Profile A: B's outbound to C. Profile B: inbound on A's coordination onion
service.

| State | Event | Action | Next |
|-------|-------|--------|------|
| OPEN | message other than `version`, `verack`, `feature`, `ping`, `pong`, `rendezvous`, `punch` (Profile B endpoint) | disconnect (R-12.2) | CLOSED |
| OPEN | second `rendezvous` or second `punch` on this connection | disconnect (R-4.4) | CLOSED |
| OPEN | `COORD_TIMEOUT_MS` without `punch` (B) / without completed handshake (A, Profile B) | disconnect | CLOSED |
| OPEN | `WINDOW_MS + GRACE_MS` after `punch` | party may close; coordinator may close | CLOSED |
