# State tables for the coordinator-less TCP hole punching BIP draft (v0.2)

Each table lists (state, event, action, next state). Rule numbers refer
to the main document. Events not listed for a state are ignored, except
protocol errors, which close the connection they arrived on. No
connection has to be retained for this protocol (R-8.11).

## Session (one per pick, R-7.4)

Key: (local punch port, entry endpoint). Window = `WINDOW_MS` from the
session start, which is the start of the round that picked the entry.
The role is fixed at the pick from the pair value (R-4.7).

| State | Event | Action | Next |
|-------|-------|--------|------|
| (none) | round picks the entry | reserve inbound slot (responder) or hole-punch outbound slot (initiator); remove the entry from the table (R-7.6); open punch-port socket; `connect(endpoint)` and leave it pending | PUNCHING |
| PUNCHING | attempt fails (refused, reset, unreachable, OS timeout, other error) | close socket; start retry timer (`RETRY_MS`, doubled per failure) | WAITING_RETRY |
| PUNCHING | attempt fails because the 4-tuple is in use | close socket; do not retry; await a matching listener socket until the session deadline (R-8.3) | PUNCHING |
| WAITING_RETRY | retry timer fires, window not over | open punch-port socket; `connect(endpoint)` | PUNCHING |
| PUNCHING | `connect()` completes, remote endpoint == entry endpoint | session connection = this socket; initiator: send BIP 324 key; responder: wait | ESTABLISHED |
| (none) | listener accepts a socket that matches no session | hold it untouched for `HOLD_MS`, at most `HELD_MAX`; close it then, or when evicted by a newer one (R-8.4) | (none) |
| (none) | round picks an entry while a held socket matches its endpoint | session connection = the held socket; initiator: send BIP 324 key; responder: wait | ESTABLISHED |
| PUNCHING / WAITING_RETRY | listener accepts socket with remote endpoint == entry endpoint | close pending attempt; session connection = accepted socket; initiator: send BIP 324 key; responder: wait | ESTABLISHED |
| PUNCHING / WAITING_RETRY | window timer fires | close pending attempt; start `GRACE_MS` timer | GRACE |
| GRACE | listener accepts socket with remote endpoint == entry endpoint | as above | ESTABLISHED |
| ESTABLISHED (responder) | BIP 324 bytes arrive | complete handshake as responder | HANDSHAKE |
| ESTABLISHED (responder) | v1 prefix arrives | close connection; release slot | FAILED |
| ESTABLISHED (responder) | peer closes before any byte arrived | drop the socket; resume attempts (R-8.5) | WAITING_RETRY |
| ESTABLISHED (initiator) | BIP 324 handshake completes | send `version` | HANDSHAKE |
| any non-terminal | `WINDOW_MS + GRACE_MS` after session start, without `verack` | close all session sockets; release slot | FAILED |
| HANDSHAKE | `verack` received | account per R-9.1 (initiator: hole-punch outbound, responder: inbound) | CONNECTED |
| HANDSHAKE | disconnect before `verack` | release slot | FAILED |
| any non-terminal | shutdown or punch port closed | close all; release slot | FAILED |

Terminal: CONNECTED, FAILED (I-6). Nothing is reported or retried (R-8.9).

## Punch-port listener

| State | Event | Action | Next |
|-------|-------|--------|------|
| LISTENING | accept yields socket whose remote endpoint matches an active session's endpoint | hand to that session | LISTENING |
| LISTENING | accept yields socket matching no session | hold for `HOLD_MS`, at most `HELD_MAX` (R-8.4, I-2) | LISTENING |

## Node, per address family (external address and announcing)

| State | Event | Action | Next |
|-------|-------|--------|------|
| NOT_EIM | exactly one endpoint has reports from at least two connected peers in distinct network groups | external address = that endpoint | HAS_ADDRESS |
| HAS_ADDRESS / READY | a second endpoint has reports from at least two connected peers in distinct network groups | drop external address; stop announcing (R-2.3) | NOT_EIM |
| HAS_ADDRESS / READY | fewer than two distinct network groups still report the external address | drop external address; stop announcing (R-2.2, R-2.4) | NOT_EIM |
| HAS_ADDRESS | external address port is not a bad port; free hole-punch outbound slot or free inbound slot (reserved slots count as used) | eligible to announce | READY |
| READY | announce timer (`ANNOUNCE_INTERVAL` per peer), or key or external address just changed | send `PUNCHKEY(net, addr, pubkey)` with `time = now` to peers that sent the feature and `sendaddrv2` (R-5.4) | READY |
| READY | no free slot of either kind, or external address dropped | stop announcing (entries elsewhere age out) | HAS_ADDRESS / NOT_EIM |
| HAS_ADDRESS / READY | external address changed | replace key (R-4.3); announce again only under the new key | HAS_ADDRESS |

## Key (one per node, R-4.1 to R-4.3)

| State | Event | Action | Next |
|-------|-------|--------|------|
| (none) | startup | generate (`p`, `P`) from fresh randomness; schedule rotation at an unaligned time within `KEY_ROTATE_H` | CURRENT |
| CURRENT | an announced external address changes | generate new key; discard old secret; pair values use the new key only; announce promptly | CURRENT |
| CURRENT | rotation timer fires | as above | CURRENT |

## Announcement table (section 6)

| State | Event | Action | Next |
|-------|-------|--------|------|
| any | `PUNCHKEY` element received that fails R-5.1, carries own key or own address (R-5.6), or exceeds the peer's `PUNCHKEY_PER_HOUR` (R-5.5) | ignore | any |
| any | valid element, (endpoint, pubkey) already stored | `last_seen = now`; `time = max(time, element.time)`; keep `received_at`; relay if not relayed within `RELAY_TTL` (R-6.1, R-5.3) | any |
| any | valid new element; source group below `SOURCE_CAP`, table below `TABLE_MAX` | store with `received_at = last_seen = now`, compute the shared secret; relay (R-6.1, R-5.3) | any |
| any | valid new element; source group at `SOURCE_CAP` | evict an expired entry of that group, else a random one; store; relay (R-6.2) | any |
| any | valid new element; table at `TABLE_MAX` | evict an expired entry, else a random entry of the largest source group; store; relay (R-6.3) | any |
| any | `getaddr` from a peer that sent the feature and `sendaddrv2` (OPTIONAL, R-5.7) | append up to `SYNC_MAX` random unexpired entries to the response | any |
| any | `ENTRY_TTL` after `last_seen` | expired: excluded from rounds, may be removed (R-6.4) | any |
| any | round picks an entry | remove it (R-7.6) | any |
| any | restart | empty table (R-6.6) | any |

## Round (section 7)

| State | Event | Action | Next |
|-------|-------|--------|------|
| IDLE | active tip changes; in initial block download, or the height did not increase, or `B` already had a round | no round (R-7.1) | IDLE |
| IDLE | tip advances to `B`, no free slot of either kind | skip the round | IDLE |
| IDLE | tip advances to `B` | eligible = entries with `received_at` before the tip reached `B`'s parent (R-7.2); candidates = eligible entries passing R-7.3 with the role from R-4.7; compute pair values (R-4.5); sort ascending (R-4.6) | PICKING |
| PICKING | next candidate; its network group or source group equals that of a pick already taken, or the slot its role needs was reserved meanwhile | skip it (R-7.4) | PICKING |
| PICKING | `PICKS_PER_ROUND` picks made, or another session would exceed `MAX_ACTIVE_SESSIONS`, or list exhausted | stop | IDLE |
| PICKING | next candidate accepted | reserve the slot for its role; start Session with the round start as session start (R-7.4) | PICKING |
