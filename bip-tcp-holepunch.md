```
  BIP: ?
  Layer: Peer Services
  Title: TCP Hole Punching for Peer Connections
  Authors: TBD
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Discussion: 2026-05-11: https://delvingbitcoin.org/t/tcp-hole-punching-for-bitcoin-nodes-behind-home-nats/2497
  Version: 0.3.0
  Requires: 155, 324, 434
```

## Abstract

This document specifies how two Bitcoin nodes that cannot accept incoming
TCP connections, because each sits behind a NAT with endpoint-independent
mapping or behind a stateful firewall, establish a direct TCP connection
to each other by TCP simultaneous open ("hole punching").

A node dedicates one local port per address family, the *punch port*, to
all of its outbound connections. Every peer then reports in its `version`
message the NAT-mapped address and port of that node, so no separate
discovery protocol is needed. Two small messages, `rendezvous` and `punch`,
carried over an existing connection to a *coordinator*, tell the
two nodes whom to connect to and who speaks first. A new BIP 155 address
type announces that a node can be reached this way.

The coordinator is either a third node that both parties are
connected to (Profile A) or a dedicated Tor onion service run by the node
that wants inbound connections (Profile B). Both profiles use the same two
messages and are included in this draft; a later revision is expected to
retain one.

## Copyright

This BIP is licensed under the BSD-2-Clause License. Auxiliary code in
`bip-tcp-holepunch/` is additionally licensed under the MIT License.

## Motivation

A large share of Bitcoin nodes run on residential connections behind a
NAT and never accept inbound connections. Enabling PCP/NAT-PMP port mapping
by default in Bitcoin Core v30 did not measurably increase the number of
reachable residential nodes[^natpmp]. Such nodes consume inbound slots of
reachable nodes without offering any.

TCP hole punching lets two such nodes connect directly without relaying
traffic through a third party. A survey among developers[^survey] found
that roughly two thirds of residential IPv4 NATs use endpoint-independent
mapping, for which hole punching works, and that IPv6 deployments are
usually "no NAT, stateful firewall", which the same procedure traverses.
Measurements of libp2p's DCUtR protocol report about 70% success for TCP
hole punching at Internet scale[^dcutr-measurement].

Hole-punched connections are a best-effort addition. They do not replace
ordinary inbound and outbound connections, port mapping, or privacy
networks. The goal is extra connection slots and more peer diversity for
nodes that currently have none to offer.

## Scope

This specification supports pairs of nodes that both have
endpoint-independent mapping (EIM) in the sense of RFC 4787, including
nodes that have no NAT but a stateful firewall. NATs with address-dependent
or address-and-port-dependent mapping ("symmetric" NATs, common with
carrier-grade NAT and mobile networks) are out of scope: a node that
detects such a NAT does not participate. Filtering behaviour
(endpoint-independent or address-and-port-dependent) does not matter; the
retry schedule covers the first dropped SYN.

Participation is opt-in. A node that does not enable it behaves exactly as
before, and nothing in this document changes how ordinary connections are
made or accounted.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

Integer fields are little-endian unless the name ends in `_be`.
`CompactSize` is the variable-length integer used elsewhere in the P2P
protocol, minimally encoded.

**Endpoint.** A transport address encoded as a BIP 155 address element
without `time` and `services`:

| Type          | Name       | Description |
|---------------|------------|-------------|
| `uint8`       | `net`      | BIP 155 network ID, `IPV4` (1) or `IPV6` (2) |
| `CompactSize` | `addr_len` | 4 for `IPV4`, 16 for `IPV6` |
| `uint8[]`     | `addr`     | address bytes |
| `uint16_be`   | `port`     | port, big-endian as in BIP 155 |

**Punch port.** A local TCP port per address family that a participating
node reserves for this protocol. The default is the node's own P2P port
plus two (8335 for a mainnet node on the default port); implementations
make it configurable. It is independent of whether the node listens for
ordinary inbound connections.

**Punch-port socket.** A TCP socket bound to the punch port with
`SO_REUSEADDR` and `SO_REUSEPORT` set before binding.

**Reported address.** The address and port a peer puts in the `addr_recv`
field of its `version` message: the source of the connection as that peer
sees it[^addr-recv]. Only reports on outbound connections using a
punch-port socket without a proxy count ("reporting peers").

**External address.** A node's address and port as seen from the
Internet, for one address family: the reported address that at least two
currently connected reporting peers in distinct network groups agree on.
It remains valid only while that agreement holds and no second agreeing
set reports a different endpoint (R-2.2, R-2.3).

**Network group.** The grouping an implementation uses for outbound peer
diversity (for example /16 for IPv4, /32 for IPv6, or autonomous systems).

**Parties.** The **advertiser** (A) wants inbound connections. The
**connector** (B) wants an outbound connection to A. The **coordinator**
(C) relays between them. In Profile B, A is its own coordinator.

**Roles.** Each session has one **initiator** and one **responder**, in
the sense of BIP 324: the initiator sends the first bytes. The role is
assigned by `punch` and never derived from whether the operating system
delivered the socket via `connect()` or `accept()`.

**Session.** The local state identified by the pair (local punch port,
peer endpoint). Its start time is the receipt of a `punch` that passes
R-5.1. For a Profile B advertiser, which receives no `punch`, it is the
acceptance of a validated `rendezvous` under R-12.5.

## Specification

### 1. Sockets

- R-1.1 A participating node MUST make every outbound TCP connection to an
  `IPV4` or `IPV6` peer that is not reached through a proxy from a
  punch-port socket of the peer's address family[^bind-all]. If the
  operating system refuses the connection because the 4-tuple is still in
  use (typically `TIME_WAIT` after a recent connection to the same peer),
  the node MAY use an ephemeral port instead; such a connection is not a
  reporting peer and MUST NOT set `PUNCHPORT`.
- R-1.2 A participating node MUST listen on each punch port. Connections
  accepted there are punched connections; the listener MUST NOT be used
  for anything else.
- R-1.3 Punch connect attempts use punch-port sockets, are non-blocking,
  and a superseded attempt MUST be closed.
- R-1.4 IPv4-mapped IPv6 addresses MUST NOT appear in endpoints, reports,
  or connect targets. Sockets are per address family. Punch-port sockets
  SHOULD be bound to a stable local address; IPv6 temporary addresses
  (RFC 8981) make reports disagree and yield no external address.

### 2. External address and the EIM check

- R-2.1 A node MUST ignore reports from proxied connections, from
  connections not made from a punch-port socket, reports whose address is
  not globally routable, and reports with port 0.
- R-2.2 A node has an external address for an address family when at least two
  current reporting peers in distinct network groups report the same endpoint.
  Reports from only one network group do not qualify an endpoint. A lone
  dissenting report cannot replace or invalidate an agreeing set.
- R-2.3 If two such agreeing sets report different endpoints for the same
  family, the node's mapping is not endpoint-independent, or it has several
  external addresses. It then has no external address and MUST NOT announce or
  send `rendezvous` for that family until R-2.2 yields a single endpoint
  again.
- R-2.4 An external address that stops being valid MUST NOT be used in new
  announcements or requests. Sessions already started continue.
- R-2.5 On test networks such as regtest, where all nodes share one host,
  an implementation MAY waive the requirement that addresses be globally
  routable (R-2.1, R-5.1, R-6.1) and MAY treat each peer as its own
  network group, so that the procedure can be exercised end to end.

### 3. Signalling

- R-3.1 Support is negotiated per connection with a BIP 434 `feature`
  message. The `featureid` is `https://delvingbitcoin.org/t/2497` until a
  BIP number is assigned, then `BIP<n>`. The `featuredata` is:

  | Type     | Name      | Description |
  |----------|-----------|-------------|
  | `uint8`  | `version` | 0 for this document |
  | `uint32` | `caps`    | capability bits, see below |

  | Bit | Name          | Meaning |
  |-----|---------------|---------|
  | 0   | `COORDINATOR` | the sender acts as coordinator (Profile A) |
  | 1   | `ADVERTISED`  | the sender is, or will be, advertised through the receiver and accepts `punch` as responder for sessions requested by others |
  | 2   | `POOL_OK`     | the sender may be paired with another pool member by the receiver |
  | 3   | `HANDOFF_OK`  | the sender accepts a handoff instead of eviction on this connection |
  | 4   | `PUNCHPORT`   | this outbound connection uses the sender's punch port without a proxy |

  Unknown bits MUST be ignored. `PUNCHPORT` MUST only be set on an
  outbound connection using a punch-port socket without a proxy.
  A receiver MUST only act on it for inbound connections. On punched
  connections, direction is determined by R-8.1, independently of whether
  the socket was obtained through `connect()` or `accept()`. A node
  MUST NOT send `rendezvous` or `punch` on a connection unless both sides
  sent the feature with `version` 0. Receiving either message otherwise
  MUST result in disconnect.
- R-3.2 Future versions of this protocol are negotiated through the
  `version` field of the feature data; nodes MUST NOT send `rendezvous` or
  `punch` to a peer whose feature `version` differs from their own.
- R-3.3 Participating nodes MUST advertise `NODE_P2P_V2`.
- R-3.4 No BIP 324 1-byte message type IDs are assigned; the messages use
  the 13-byte encoding. A connection may carry repeated coordination
  exchanges, subject to R-4.4 and the session and request limits.

### 4. Messages

#### `rendezvous` (connector to coordinator)

| Type     | Name        | Description |
|----------|-------------|-------------|
| endpoint | `target`    | the advertiser's endpoint from the announcement |
| endpoint | `requester` | the connector's external address in the same address family |

#### `punch` (coordinator to a party)

| Type     | Name   | Description |
|----------|--------|-------------|
| `uint8`  | `role` | 0 responder, 1 initiator |
| endpoint | `peer` | the other party's endpoint |

- R-4.1 Fields appear in the order given; trailing or missing bytes make
  the message malformed and the sender MUST be disconnected.
- R-4.2 An endpoint with `net` other than `IPV4` or `IPV6`, an `addr_len`
  that does not match `net`, or a `role` other than 0 or 1 is malformed.
- R-4.3 Both fields of `rendezvous` MUST have the same address family.
- R-4.4 A `rendezvous` is *outstanding* from when it is sent until an
  answering `punch` is accepted on the same connection or
  `COORD_TIMEOUT_MS` elapses from sending the request. A party MUST NOT
  send a `rendezvous` while one is outstanding on that connection. Every
  `punch` received while the request is outstanding is an answering
  `punch` and MUST be checked against that request under R-5.1. Only an
  initiator `punch` whose `peer` equals the request's `target` and which
  passes the remaining R-5.1 checks completes the request. A rejected
  `punch` MUST NOT clear the request or restart its deadline; subsequent
  `punch` messages remain answering messages until acceptance or timeout.
  A `punch` received with no outstanding request is *unsolicited*. A
  coordinator MUST NOT send a `punch` to a party within
  `WINDOW_MS + GRACE_MS` of a previous `punch` it sent to that party.

### 5. Punch procedure

#### Validation

- R-5.1 On receiving `punch`, a node MUST ignore it, and MAY close the
  connection, if any of the following holds:
  - `peer` is not globally routable, is one of the node's own addresses or
    external addresses, or has port 0, or the node has no punch port for its
    family;
  - the `punch` answers a `rendezvous` (R-4.4) but `role` is not initiator or
    `peer` does not equal that `rendezvous`'s `target`; this is the
    anti-redirection check: a coordinator cannot steer the connector
    anywhere but to the announced target;
  - the `punch` is unsolicited and the node did not set, on this connection,
    `ADVERTISED` (for role responder) or `POOL_OK` or `HANDOFF_OK` (for either
    role), or the role is initiator and `peer` fails the diversity rule of
    R-7.1 with the sender counted as its coordinator;
  - a session with the same (punch port, `peer`) exists, the node has
    `MAX_ACTIVE_SESSIONS` (2) sessions, started `SESSIONS_PER_MIN` (4)
    sessions in the last minute, or started one to the same address within
    `PER_IP_INTERVAL` (10 min);
  - the role is responder and no inbound slot is free, or the role is
    initiator and the hole-punch outbound slot is taken (section 8).
- R-5.2 Endpoints whose port the implementation treats as a "bad port" for
  outbound connections SHOULD be ignored.
- R-5.3 A responder MUST reserve one inbound slot for the session until it
  terminates.

#### Attempts

- R-5.4 On accepting a `punch`, the node immediately opens a punch-port
  socket and calls `connect()` on `peer`, with a deadline at the end of the
  window (`WINDOW_MS`, 15000 ms after session start). At this
  deadline the node MUST close any pending attempt and MUST NOT start
  further attempts. It continues to accept matching sockets from the
  punch-port listener until the session deadline in R-5.11.
- R-5.5 If an attempt fails before the deadline (connection reset,
  unreachable, or any immediate error), the node MUST close the socket,
  wait `RETRY_MS` (1000 ms), and open a new attempt, until the deadline.
  The pending `connect()` itself retransmits SYNs; the node MUST NOT run
  more than one attempt at a time per session.
- R-5.6 An attempt that fails because the 4-tuple is already in use MUST
  be closed and MUST NOT be retried. This error alone does not establish
  the session. The node waits for a matching socket from the punch-port
  listener (R-5.7) until the session deadline in R-5.11.

#### Establishment

- R-5.7 The session's connection is the first socket whose remote endpoint
  equals `peer` exactly, obtained either by a completed `connect()` of
  this session or by `accept()` on the punch-port listener. Because both
  parties use fixed ports, at most one TCP connection can exist per
  session. A socket accepted on the punch-port listener that matches no
  session MUST be closed.
- R-5.8 On establishment the node stops the attempts. The initiator
  immediately sends its BIP 324 initiator bytes. The responder sends nothing
  until BIP 324 bytes arrive.
- R-5.9 The punched connection MUST use the BIP 324 v2 transport. A v1
  prefix on the connection is an error; the connection MUST be closed and
  no v1 fallback attempted.
- R-5.10 The ordinary `version`/`verack` handshake follows on the encrypted
  connection; the initiator sends `version` first. The session is complete
  when the node has received `verack`.

#### Termination

- R-5.11 A session ends when its connection has completed `verack`
  (success) or at the absolute deadline `WINDOW_MS + GRACE_MS`
  (17000 ms after session start) without that (failure).
  Handshake progress MUST NOT extend this deadline. On failure every
  socket of the session MUST be closed and the reserved slot released.
- R-5.12 No outcome is reported over the protocol. A coordinator
  learns of success only indirectly; an advertiser that still has free
  slots simply remains available.

#### Timing and mapping liveness

- R-5.13 In Profile A, both parties start on receipt of `punch`. The
  coordinator sends the two `punch` messages back to back, the one for the
  responder first. In Profile B, the advertiser starts on acceptance of
  the validated `rendezvous`, and the connector on receipt of `punch`.
  Their deadlines are measured from their respective session start times.
- R-5.14 In Profile A the coordinator MUST keep both connections open for
  `WINDOW_MS + GRACE_MS` after sending `punch`: they are punch-port
  connections that keep the parties' NAT mappings alive. In Profile B the
  coordination connection is proxied and keeps nothing alive, so A closes
  it after writing `punch` to the socket as specified in R-12.5. R-1.1
  makes any node with outbound peers keep its mapping alive regardless.

### 6. Announcements: the `HOLEPUNCH` address type

This document reserves BIP 155 network ID `0x08`, enumeration
`HOLEPUNCH`. The `addr` field is:

| Type        | Name          | Description |
|-------------|---------------|-------------|
| `uint8`     | `coord_net`   | `IPV4` (1), `IPV6` (2), `TORV3` (4), or `I2P` (5) |
| `uint8[]`   | `coord_addr`  | coordinator's address, 4, 16, 32, or 32 bytes |
| `uint16_be` | `coord_port`  | coordinator's port; MUST be 0 for `I2P` |
| `uint8`     | `target_net`  | `IPV4` or `IPV6` |
| `uint8[]`   | `target_addr` | the advertiser's external address, 4 or 16 bytes |

The element's `port` field is the port of the advertiser's external address,
`services` the advertiser's services (MUST include `NODE_P2P_V2`), and `time`
the announcement time. Valid `addr` lengths are 12, 24, 36, 40, and 52 bytes;
the field is parsed by network IDs, and length 24 occurs for both (`IPV6`,
`IPV4`) and (`IPV4`, `IPV6`).

A clearnet `coord_net` means Profile A: the coordinator is a third node.
An onion or I2P `coord_net` means Profile B: the coordinating endpoint
belongs to the advertiser itself.

- R-6.1 Receivers MUST reject elements with an invalid length, with a
  `coord_net` or `target_net` outside the sets above, or with a clearnet
  `coord_addr` or a `target_addr` that is not globally routable.
- R-6.2 **No storage.** `HOLEPUNCH` elements MUST NOT be added to the
  address manager, returned in response to `getaddr`, or persisted.
  Receivers keep them in a bounded in-memory cache of at most `CACHE_MAX`
  (32) entries with at most `CACHE_PER_PEER` (4) from one source peer,
  expiring `CACHE_TTL` (10 min) after `time`. Receivers MUST reject an
  element unless `now - CACHE_TTL < time <= now + 10 min`.
- R-6.3 **Relay.** An element MAY be relayed to a small number of peers
  that sent `sendaddrv2`, only if
  `now - CACHE_TTL < time <= now + 10 min`. Relays MUST preserve `time`;
  receiving or relaying an element MUST NOT restart its expiry timer.
  It MUST NOT be sent to peers that did not negotiate `sendaddrv2`.
  Advertisers send their element alone or in an `addrv2` message of at
  most ten elements, since implementations commonly relay only small
  messages.
- R-6.4 **Clearnet only for Profile B.** Elements with an onion or I2P
  `coord_net` MUST only be sent on connections to `IPV4` or `IPV6` peers
  not reached through a proxy, so the coordination identity never appears
  on the privacy network itself.
- R-6.5 **Self-announcement.** An advertiser announces only while it has
  at least one free inbound slot, counting slots reserved by sessions
  (R-5.3) as used, a valid external address (R-2.2), and, in
  Profile A, an open connection to the named coordinator with
  `ADVERTISED` and `PUNCHPORT` set; at most once per `ANNOUNCE_INTERVAL`
  (10 min) per peer. An advertiser announces one element at a time; in
  Profile A it MAY name a different coordinator in a later announcement.
- R-6.6 Elements count against the receiving peer's address rate limit as
  one address each.

### 7. Connector behaviour

- R-7.1 A connector chooses targets only from its cache. An entry is eligible
  if the connector can reach `coord_net`, has an external address in
  `target_net`'s family, has its hole-punch outbound slot free, and if
  `target_addr` and, in Profile A, `coord_addr` pass the connector's
  network-group diversity rules against its existing outbound peers, where a
  coordinator and every target announced through it count as one
  group[^one-group]. In Profile A, exclude only an existing
  outbound connection to the exact named coordinator endpoint
  `coord_addr:coord_port`. Every other outbound peer remains in the
  comparisons, including peers in the coordinator's network group. Both
  `coord_addr` and `target_addr` MUST pass against the remaining peers.
  The same exception applies when R-5.1 treats the sender of an unsolicited
  initiator `punch` as its coordinator: exclude only that sender's exact
  endpoint, and require the proposed peer to pass against all remaining
  outbound peers.
- R-7.2 A connector MUST NOT start more than one coordination attempt per
  `HP_ATTEMPT_INTERVAL` (5 min) and MUST drop a cache entry after one
  attempt, whatever its outcome.
- R-7.3 Profile A: the connector reuses an existing outbound connection
  to `coord_addr:coord_port` only if it sent `PUNCHPORT` on that connection.
  Otherwise it opens one from a punch-port socket with `PUNCHPORT` set.
  Before sending `rendezvous`, it MUST complete the feature exchange and
  verify that the coordinator advertised `COORDINATOR`. Profile
  B: it opens a connection over Tor (or I2P) to `coord_addr` with stream
  isolation. In both cases the response deadline is `COORD_TIMEOUT_MS`
  (10000 ms) after sending `rendezvous`. If no accepted answering `punch`
  arrives by that deadline, the connector gives up and closes a connection
  it opened only for coordination. After accepting an answering `punch` in
  Profile A, it MUST keep such a connection open until
  `WINDOW_MS + GRACE_MS` after receipt of that `punch`, even if the session
  completes earlier. An existing ordinary connection is not closed merely
  because coordination ends.
- R-7.4 A connection to a dedicated Profile B coordination endpoint carries
  only `version`, `verack`, `feature`, `ping`, `pong`, `rendezvous`, and
  `punch`; receiving any other message on it MUST result in disconnect.
  Profile A uses ordinary P2P connections and permits ordinary P2P messages,
  including on connections opened only for coordination.

### 8. Classification and slots

- R-8.1 The initiator accounts the punched connection as a **hole-punch
  outbound**, one slot in addition to its ordinary automatic outbound slots
  (`HP_OUTBOUND_MAX` = 1). A node MUST NOT use it as an anchor and MUST NOT
  count it when deciding whether its outbound connectivity is diverse enough
  to record address manager failures[^extra-slot]. The responder accounts the
  connection as inbound. This holds for every session, whether requested by
  the connector or created by a coordinator for a pool or handoff pairing: the
  initiator is the party that acts as BIP 324 initiator and sends `version`
  first, exactly as for any outbound connection[^initiator-slot].

### 9. Invariants

| ID | Invariant | Test shape |
|----|-----------|------------|
| I-1 | Each session has exactly one initiator. The initiator sends the first bytes (BIP 324 key, then `version`); the responder sends nothing before receiving BIP 324 bytes. | Force roles on two nodes; capture first bytes on the wire. |
| I-2 | A session is keyed by (punch port, peer endpoint) and has at most one connection, whose remote endpoint equals `peer` exactly. A socket accepted on the punch port that matches no session is closed. | Connect to the punch port from an unexpected endpoint; assert close. |
| I-3 | Every non-proxied clearnet outbound connection, every punch attempt, and the listener of one family share the punch port, except connections that fell back to an ephemeral port per R-1.1, which never set `PUNCHPORT`. | Inspect local ports of all sockets. |
| I-4 | Connect attempts go only to the `peer` of an accepted `punch` that is routable, not local, not the node's own address, same family, and, when the `punch` answers a `rendezvous`, equal to its `target`; one attempt at a time per session; at most `WINDOW_MS / RETRY_MS + 1` attempts per session. | Feed invalid `punch` and a redirecting `punch`; count SYNs with a socket mock. |
| I-5 | At most `MAX_ACTIVE_SESSIONS` concurrent, `SESSIONS_PER_MIN` per minute, one per remote address per `PER_IP_INTERVAL`. | Flood `punch`; assert ignores. |
| I-6 | Every session ends within `WINDOW_MS + GRACE_MS` in success or failure and releases every socket except the session connection and the reserved slot. | Drive sessions to both outcomes; compare socket counts. |
| I-7 | `HOLEPUNCH` elements never enter the address manager, `getaddr` responses, or persisted files, and are not relayed outside the time window. | Send elements; query address manager and `getaddr`; restart. |
| I-8 | A hole-punch outbound exists only as the initiator side of a session, at most `HP_OUTBOUND_MAX` at a time, never as an anchor; its `peer` passes diversity with the coordinator as one group, and for a solicited session equals the `rendezvous` target. | Coordinator supplies a different `peer`; assert no attempt. |
| I-9 | Punched connections use BIP 324 without v1 fallback; both parties advertise `NODE_P2P_V2`. | Send v1 `version` on a punched connection; assert close. |
| I-10 | A node has an external address only while two reporting peers in distinct network groups agree on its endpoint and no second agreeing set disagrees (R-2.2, R-2.3); it announces only with an external address and a free inbound slot; a responder reserves one slot per session. | One dissenting report: external address kept. Two agreeing dissenting reports: external address dropped, no announcement. |
| I-11 | A coordinator never relays application bytes, puts only endpoints it observed into `punch`, keeps both connections open `WINDOW_MS + GRACE_MS` after `punch`, sends no second `punch` to a party within that time, and never pairs parties sharing an address. | Coordinator unit tests. |
| I-12 | The Profile B coordination service uses a key not used for anything else, rotates it at least every `ONION_ROTATE_H` (24 h), is never advertised through local address discovery or `getaddr`, and its announcements leave only on clearnet connections. | Compare onion ids; assert no element on onion peers. |

### 10. Limits

| Name | Default | Used in |
|------|---------|---------|
| punch port | own P2P port + 2 | Terminology |
| `WINDOW_MS` | 15000 | R-5.4 |
| `RETRY_MS` | 1000 | R-5.5 |
| `GRACE_MS` | 2000 | R-5.11 |
| `MAX_ACTIVE_SESSIONS` | 2 | R-5.1 |
| `SESSIONS_PER_MIN` | 4 | R-5.1 |
| `PER_IP_INTERVAL` | 10 min | R-5.1 |
| `COORD_TIMEOUT_MS` | 10000 | R-4.4, R-7.3, R-12.2 |
| `COORD_INBOUND_MAX` | 8 | R-12.2 |
| `CACHE_MAX` / `CACHE_PER_PEER` / `CACHE_TTL` | 32 / 4 / 10 min | R-6.2 |
| `ANNOUNCE_INTERVAL` | 10 min | R-6.5 |
| `HP_ATTEMPT_INTERVAL` | 5 min | R-7.2 |
| `HP_OUTBOUND_MAX` | 1 | R-8.1 |
| `ONION_ROTATE_H` | 24 h | R-12.1 |

### 11. Profile A: coordinator

Any peer that sets `COORDINATOR` in its feature can act as coordinator.
Advertisers use coordinators among their existing outbound peers; they do
not need a separate discovery mechanism.

- R-11.1 A coordinator keeps, for each inbound connection with
  `PUNCHPORT` set, the endpoint it observed. Only observed endpoints go
  into `punch`, never the `requester` field of `rendezvous`.
- R-11.2 On `rendezvous` from an inbound peer B, the coordinator looks for an
  inbound connection A with `ADVERTISED` and `PUNCHPORT` whose observed
  endpoint equals `target`. It MUST NOT send `punch`, and MAY close B's
  connection, if there is none; if B did not set `PUNCHPORT` or its
  `requester` differs from B's observed endpoint (B's mapping is not
  endpoint-independent towards the coordinator and the punch would fail);
  if A or B is within `WINDOW_MS + GRACE_MS` of a previous `punch`; if A
  and B share an address; if the families differ; or if more than
  `SESSIONS_PER_MIN` requests named A in the last minute. B gives up after
  `COORD_TIMEOUT_MS`.
- R-11.3 Otherwise the coordinator sends `punch(role=responder, peer=B's
  observed endpoint)` to A and `punch(role=initiator, peer=A's observed
  endpoint)` to B, in that order, and applies R-5.14.
- R-11.4 A coordinator SHOULD NOT evict an inbound peer within
  `WINDOW_MS + GRACE_MS` of a `punch` it sent to it, and SHOULD prefer
  to keep peers with `ADVERTISED` set, whose announcements name it.

#### A.1 Targeted rendezvous (REQUIRED for Profile A)

```
 A (advertiser)                C (coordinator)                B (connector)
 -- connection from punch port, feature(ADVERTISED|PUNCHPORT) -->
 ... A announces HOLEPUNCH(coord=C, target=A's address) on the network ...
                                                           cache entry chosen
                               <-- existing or new connection from punch port --
                               <-- rendezvous(target=A, requester=B) --
 <-- punch(responder, peer=B) --  -- punch(initiator, peer=A) -->
               ====== simultaneous open A:punch <-> B:punch ======
               <===== BIP 324 (B initiates), version/verack =====>
```

- R-11.5 A announces `coord_*` set to the address it used to connect to C and
  `target_*` set to its external address; it MUST keep the connection to C
  open while the announcement is valid (R-6.5).
- R-11.6 B checks `peer` against `target` (R-5.1) and accounts the
  connection per R-8.1.

#### A.2 Matchmaking pool (OPTIONAL)

- R-11.7 Peers with `POOL_OK` and `PUNCHPORT` form the coordinator's
  pool. The coordinator MAY pair two members whose observed addresses
  differ, preferring different network groups, at most once per
  `PER_IP_INTERVAL` for the same pair.
- R-11.8 The initiator is the member whose observed endpoint, serialized as an
  endpoint, is lexicographically smaller. Both members account the connection
  per R-8.1.

#### A.3 Handoff instead of eviction (OPTIONAL)

- R-11.9 When a coordinator's inbound capacity is exhausted and its
  eviction rules select peer X, it MAY first pair X with another inbound
  peer Y, if both have `HANDOFF_OK` and `PUNCHPORT`, have completed
  `verack`, do not share an address, and have no elevated permissions: it
  sends `punch` to both with roles per R-11.8, keeps both connected for
  `WINDOW_MS + GRACE_MS`, and then disconnects X. The coordinator exceeds
  its inbound limit by one connection for that time. Both parties account
  the connection per R-8.1.

#### Trust considerations for coordinators

The coordinator learns that A and B were paired and when, and anyone who sees
A's announcement learns that A is connected to C. It can refuse to pair and
can send a wrong `peer`: a connector rejects any `peer` other than the
announced target before sending a SYN (R-5.1), and an advertiser or pool
member spends at most one session's attempts (R-5.5). It cannot read or modify
the punched connection. In every session the initiator holds one extra
outbound slot that is excluded from anchors and diversity accounting (R-8.1),
and the peer must pass diversity with the coordinator and its targets as one
group (R-7.1, R-5.1).

### 12. Profile B: self-coordinated over Tor

The advertiser runs a Tor v3 onion service dedicated to this protocol and
acts as its own coordinator. I2P endpoints are permitted through
`coord_net` = `I2P` with the same rules; I2P specifics are out of scope.

- R-12.1 The coordination onion service MUST use a key not used for any
  other purpose, MUST NOT be added to the node's local address list or
  returned via `getaddr`, and MUST be replaced by a fresh key at least
  every `ONION_ROTATE_H` (24 h)[^rotation]. An identity MUST stop being
  announced no later than `ONION_ROTATE_H` after its first announcement,
  even if the replacement descriptor has not yet been published. Its
  virtual port is the network's default P2P port. Implementations SHOULD
  terminate it on a distinct local bind address so that inbound connections
  on it are recognisable as coordination connections. A new address MUST
  only be announced once its descriptor is published. The previous service
  SHOULD stay reachable for `CACHE_TTL + 10 min` after its last
  announcement; the additional ten minutes allows for clock skew within
  R-6.2's future timestamp allowance. Retiring services MUST NOT be
  announced again.
- R-12.2 Connections accepted on the coordination endpoint are
  coordination-only connections (R-7.4). The advertiser MUST NOT hold more
  than `COORD_INBOUND_MAX` (8) of them in total across current and
  retiring endpoints. It MUST close one that has not completed `verack`,
  the feature exchange, and a `rendezvous` within `COORD_TIMEOUT_MS` of
  socket acceptance. This deadline includes transport negotiation.
- R-12.3 The advertiser announces `coord_*` set to the onion service and the
  default port and `target_*` set to its external address, subject to R-6.4
  and R-6.5.

```
 A (advertiser, own onion coordination service)             B (connector)
 ... A announces HOLEPUNCH(coord=onion, target=A's address) on clearnet ...
                                                           cache entry chosen
 <-- Tor connection (stream isolation), feature exchange -----------------
 <-- rendezvous(target=A's addr, requester=B's addr) ---------------------
 -- punch(initiator, peer=A's addr) ------------------------------------->
 (A closes the coordination connection)
               ====== simultaneous open A:punch <-> B:punch ======
               <===== BIP 324 (B initiates), version/verack =====>
```

- R-12.4 On `rendezvous`, A checks that `target` equals its current external
  address (R-2.2) and that `requester`, taken as `peer` with role responder,
  passes R-5.1. If any check fails A MUST NOT answer and MAY close the
  connection.
- R-12.5 Otherwise A starts its own session as responder with
  `peer = requester` (R-5.4) when it accepts the validated `rendezvous`,
  and sends `punch(role=initiator, peer=target)`. A MUST always assign
  initiator to the connector. A MUST write all transport bytes encoding
  `punch` to the coordination socket before closing it; queuing the message
  for later transmission is insufficient. The write MUST complete by the
  original R-12.2 deadline, without restarting that deadline or delaying
  the responder session's start. On a send failure or expiration of that
  deadline before the write completes, A MUST close the coordination
  connection and cancel any associated session still in progress, closing
  its sockets and releasing its reserved slot.
- R-12.6 B checks `peer` against `target` (R-5.1) and accounts the
  connection per R-8.1.

#### Privacy considerations for Profile B

An announcement links an onion identity to a clearnet endpoint by design.
R-12.1 and R-6.4 keep that identity separate from everything else and
short-lived. B learns that A is unreachable and A's clearnet endpoint; A
learns B's clearnet endpoint but not which Tor client connected. No third
party learns of the pairing. Because requesters are anonymous to A, only
the global limits of R-5.1 bound them; a forged `requester` costs A one
session's attempts, and holding `COORD_INBOUND_MAX` connections blocks
other requesters only for the handshake time, since A closes each
connection as soon as it has answered.

## Rationale

[^natpmp]: Observations on bnoc.xyz comparing reachable residential nodes
before and after Bitcoin Core v30 enabled `-natpmp` by default showed no
clear increase.

[^survey]: Results posted in the Delving thread using the tcp-nat-check
tool: 11 of 17 IPv4 environments were EIM, the rest address-and-port
dependent (carrier-grade NAT, campus networks, some VPNs, Docker on
macOS); IPv6, where present, had no NAT.

[^dcutr-measurement]: Trautwein et al., "Large-Scale Measurement of NAT
Traversal for the Decentralized Web", 6.25 million DCUtR attempts, about
70% success for both TCP and QUIC.

[^addr-recv]: The `version` message's `addr_recv` field has always carried
the address the sender observed for the receiver; this BIP only makes the
port meaningful by fixing the source port of outbound connections. Any
peer, upgraded or not, serves as a reporting peer.

[^bind-all]: Binding every outbound connection to the punch port makes every
peer a reporting peer, keeps the NAT mapping alive as long as the node has any
outbound connection, and removes any need for dedicated probe connections. A
peer learns that the node uses a fixed source port, which reveals nothing
beyond the node's address that it already sees. Two connections to the same
remote endpoint from one punch port are impossible: R-1.1's fallback covers
reconnecting to a peer whose 4-tuple is still in `TIME_WAIT`, and R-7.3 reuses
an existing connection to a coordinator rather than opening a second one. The
listener and the connecting sockets coexist on one port with `SO_REUSEPORT` on
Linux, the BSDs, and macOS; Windows has no equivalent and is not covered by
this draft.

[^one-group]: Proposed in the Delving thread: if the connector picks a
coordinator and then any target announced through it, the coordinator's
operator decides which target the connector ends up with; treating the set
as one group keeps the number of independent parties a connector depends
on unchanged.

[^extra-slot]: Using one of the ordinary automatic outbound slots would let
a coordinator or an announcement flood influence the selection of ordinary
peers; a dedicated extra slot bounds the influence to one connection.

[^initiator-slot]: An earlier draft accounted pool and handoff sessions as
inbound on both sides, with the initiator role only choosing who starts the
handshake. That required an "inbound" connection to act as transport initiator
and send `version` first, which implementations tie to the outbound path, and
a second classification rule. Letting the initiator always take the extra slot
gives one rule for every session; the slot is already isolated from anchors
and diversity accounting, and the coordinator-chosen peer must pass the same
diversity check as an announced target.

[^rotation]: A long-lived coordination onion address would allow anyone to
correlate successive clearnet addresses of the same node. Tor onion
service descriptors take minutes to publish, so rotation is daily rather
than per announcement.

**Why a dedicated punch port?** Reusing the P2P listening port would
require `SO_REUSEPORT` on the existing listener, a rule for telling
punched connections from ordinary inbounds on the same socket, and would
exclude nodes that do not listen at all. A dedicated port makes every
accepted connection on it a punched one and works with `-listen=0`.

**Why exact endpoint matching and no session identifiers?** Both parties
use fixed ports, so a session corresponds to exactly one TCP 4-tuple;
the kernel delivers that connection either through `connect()` or through
`accept()`, never both. Nothing else connects from the peer's punch port to
ours, so the 4-tuple identifies the session and no in-band confirmation is
needed. This is what restricting the scope to EIM buys.

**Why no v1 fallback on punched connections?** On a simultaneous open both
TCP stacks consider themselves the connecting side, so nothing in the
transport says who speaks first. BIP 324 makes the role explicit and
encrypts the link.

**Why no tokens, registration, or result messages?** The announcement
already names the target endpoint, which is unique among a coordinator's
connected peers, so the coordinator can look it up directly. Registration
is "stay connected with `ADVERTISED` set", which also keeps the NAT mapping
alive. Failure is signalled by silence and a timeout; a success is visible
to the advertiser as a new connection. Diagnostics can be added later as
optional messages.

**Why does `rendezvous` carry `requester` if the coordinator ignores it?**
Profile B has no observation of the connector and needs the field. In
Profile A it serves as a check: if it differs from what the coordinator
observes, the connector's mapping is not endpoint-independent towards the
coordinator and the punch would fail, so the coordinator refuses early.

**Why both profiles?** Profile A works without Tor and lets the coordinator
observe both endpoints directly. Profile B needs no third party and gives
the cleanest inbound/outbound semantics but requires Tor on both sides.
This draft specifies both with the same two messages so that experience
can decide; one protocol with two coordination transports is intended, not
two competing designs.

**Alternatives considered and deferred.** A reflector or STUN-like
message (not needed: `addr_recv` suffices); port prediction and
birthday-paradox probing for symmetric NATs (out of scope by design);
peer-reflexive port handling (dropped with the EIM-only scope); a sidecar
that passes connected sockets to the node (useful for experiments, not a
network protocol); UDP or QUIC transport (out of scope); a service bit for
coordinators (not needed: coordinators are found among existing peers);
a new connection type for all punched connections (rejected in favour of
inbound/outbound mapping plus one extra slot).

## Backward compatibility

Nodes that do not implement this BIP are unaffected: the `feature` message
is ignored per BIP 434, `HOLEPUNCH` elements have an unknown network ID and
are skipped by BIP 155 receivers, and `rendezvous`/`punch` are never sent to
peers that did not negotiate the feature. Nodes announcing a protocol
version below 70017 are not sent the feature.

Binding outbound connections to a fixed source port is a local change
visible to peers only as a non-ephemeral source port.

This draft describes two coordination profiles. BIP 3 asks that a BIP not
recommend two variants of an idea; the profiles share every message and
procedure and differ only in the transport of the coordination exchange.
A later revision is expected to retain one.

## Security considerations

**Reflection.** The only traffic sent to an unverified address is the
connect attempts of a session: one pending `connect()` at a time, retried
at most every second for 15 seconds, at most two concurrent sessions and
four per minute per node, one per remote address per ten minutes.
Endpoints must be routable and not local; bad ports are avoided. A
connector sends nothing unless `peer` equals the target it chose itself.
In Profile B the requester is anonymous, so these global limits are the
only bound.

**Sybil and eclipse through coordinators.** Every session gives the initiator
one extra outbound slot that is excluded from anchors and diversity
accounting. The peer must pass diversity rules with the coordinator and its
targets as one group, and a connector accepts only the announced target. An
attacker flooding announcements or acting as coordinator can obtain at most
that one slot from a victim, at the cost of one coordination attempt per five
minutes per victim.

**Topology.** A Profile A announcement states that A is connected to C,
which exposes one edge of the peer graph that is otherwise hidden.
Profile B does not reveal peers.

**Announcement spam.** `HOLEPUNCH` elements pass through the existing
address rate limits, are capped per source peer and in total in a
short-lived cache, are relayed only while fresh, and never reach
persistent storage.

**Request triggering.** In Profile B a request causes no new outbound
connection; A's external address comes from its existing peers. The number of
concurrent coordination connections and requests per minute is capped.

**Lying peers.** A peer can report any address in `addr_recv`. Only agreement
between two reporting peers in distinct network groups produces an external
address, a single dissenting report changes nothing (R-2.2), and in Profile A
the coordinator uses the address it observed itself. A wrong external address
wastes one session's attempts at most.

**Coordinator exhaustion.** Coordinators keep no state beyond the observed
endpoint of connected peers, limit requests per target and per connection,
and close idle coordination connections.

**Linkability and fingerprinting.** Profile A reveals the pairing to the
coordinator and the advertiser's NAT status to the connector. Both
profiles make a previously invisible home node's clearnet endpoint known
to the whole network, and keep doing so across address changes, which is
why participation is opt-in. Profile B reveals the advertiser's clearnet
endpoint to anyone who sees the announcement, by design; R-12.1 and R-6.4
keep that identity separate from everything else. The fixed source port
on every outbound connection and the capability bits in `feature` tell
every peer, and any passive observer on the path, that the node
participates and whether it is unreachable.

## Reference implementation

A reference implementation for Bitcoin Core is being developed on a branch
of the authors' repository and will be linked here. Test vectors and state
tables are in [`bip-tcp-holepunch/`](bip-tcp-holepunch/):
[`vectors.json`](bip-tcp-holepunch/vectors.json) generated by
[`gen_vectors.py`](bip-tcp-holepunch/gen_vectors.py), and
[`state-machines.md`](bip-tcp-holepunch/state-machines.md).

## Test vectors

`vectors.json` contains valid encodings with decoded fields and invalid
encodings with the expected rejection reason for the `feature` payload,
`rendezvous`, `punch`, and `HOLEPUNCH` address elements for every
(`coord_net`, `target_net`) combination. Implementations are expected to
accept every valid vector, reproduce its encoding byte for byte, and reject
every invalid vector.

## Changelog

* 0.3.0 (2026-10-11): initiator always takes the extra outbound slot (one
  classification rule); anti-redirection checked on `punch` receipt;
  single dissenting reports ignored; `rendezvous` reused on an
  existing coordinator connection; `TIME_WAIT` fallback; Profile B closes
  the coordination connection after `punch` and sends `peer = target`;
  handoff pairs the eviction candidate with an existing inbound; onion
  rotation overlap; `SYN_RATE` and the "no NAT" clause removed;
  `COORD_TIMEOUT_MS` 10 s; topology and fingerprinting notes; punch port
  relative to the node's own P2P port; test-network allowances (R-2.5);
  reserved inbound slots count as used when announcing.
* 0.2.0 (2026-10-10): dedicated punch port, outbound connections bound to
  it, EIM-only scope, two messages instead of seven, no session ids,
  tokens, short IDs, or service bit; messages named `rendezvous` and
  `punch`.
* 0.1.0 (2026-10-10): initial draft with both coordination profiles.

## Appendix: state machines

See [`bip-tcp-holepunch/state-machines.md`](bip-tcp-holepunch/state-machines.md)
for the session, advertiser, connector, and coordinator state tables.
