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
  Version: 0.2.0
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
carried over an existing connection to a *coordinating party*, tell the
two nodes whom to connect to and who speaks first. A new BIP 155 address
type announces that a node can be reached this way.

The coordinating party is either a third node that both parties are
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
node reserves for this protocol. The default is the network's default P2P
port plus two (8335 on mainnet). It is independent of whether the node
listens for ordinary inbound connections.

**Punch-port socket.** A TCP socket bound to the punch port with
`SO_REUSEADDR` and `SO_REUSEPORT` set before binding.

**Observer.** A peer reached through a punch-port socket without a proxy.
Its `version` message reports, in `addr_recv`, the address and port it
sees as the source of the connection[^addr-recv]; this is the observer's
**report**.

**Candidate.** A node's external endpoint for one address family: the
report shared by at least two observers in distinct address groups (see
below). A candidate is valid while at least one observer that reported it
is still connected.

**Address group.** The grouping an implementation uses for outbound peer
diversity (for example /16 for IPv4, /32 for IPv6, or autonomous systems).

**Parties.** The **advertiser** (A) wants inbound connections. The
**connector** (B) wants an outbound connection to A. The **coordinator**
(C) relays between them. In Profile B, A is its own coordinator.

**Roles.** Each session has one **punch initiator (PI)**, which acts as
the BIP 324 initiator and sends the first bytes, and one **punch
responder (PR)**. Roles are assigned by `punch` and never derived from
whether the operating system reported the socket via `connect()` or
`accept()`.

**Session.** The local state created by a `punch`, identified by the
pair (local punch port, peer endpoint).

## Specification

### 1. Sockets

- R-1.1 A participating node MUST make every outbound TCP connection to an
  `IPV4` or `IPV6` peer that is not reached through a proxy from a
  punch-port socket of the peer's address family[^bind-all].
- R-1.2 A participating node MUST listen on each punch port. Connections
  accepted there are punched connections; the listener MUST NOT be used
  for anything else.
- R-1.3 Punch connect attempts use punch-port sockets, are non-blocking,
  and a superseded attempt MUST be closed.
- R-1.4 IPv4-mapped IPv6 addresses MUST NOT appear in endpoints, reports,
  or connect targets. Sockets are per address family.

### 2. Candidates and the EIM check

- R-2.1 A node MUST ignore reports from proxied connections, reports whose
  address is not globally routable, and reports with port 0.
- R-2.2 A node has a candidate for an address family only when at least
  two observers in distinct address groups currently report the same
  endpoint. A report equal to the local bind address and punch port
  ("no NAT") counts as agreeing with any report of the same address.
- R-2.3 If two current observers report different ports for the same
  family, the node is not EIM for that family. It MUST NOT announce and
  MUST NOT send `rendezvous` for that family until the condition in R-2.2 holds
  again.
- R-2.4 A candidate that stops being valid (R-2.2 no longer holds) MUST
  NOT be used in new announcements or requests. Sessions already started
  continue.

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
  | 4   | `PUNCHPORT`   | this connection is from the sender's punch port; the endpoint the receiver observes is the sender's candidate |

  Unknown bits MUST be ignored. A node MUST NOT send `rendezvous` or `punch`
  on a connection unless both sides sent the feature with `version` 0.
  Receiving either message otherwise MUST result in disconnect.
- R-3.2 Future versions of this protocol are negotiated through the
  `version` field of the feature data; nodes MUST NOT send `rendezvous` or
  `punch` to a peer whose feature `version` differs from their own.
- R-3.3 Participating nodes MUST advertise `NODE_P2P_V2`.
- R-3.4 No BIP 324 1-byte message type IDs are assigned; the messages use
  the 13-byte encoding, as each is sent at most once per connection.

### 4. Messages

#### `rendezvous` (connector to coordinating party)

| Type     | Name        | Description |
|----------|-------------|-------------|
| endpoint | `target`    | the advertiser's endpoint from the announcement |
| endpoint | `requester` | the connector's candidate in the same address family |

#### `punch` (coordinating party to a party)

| Type     | Name   | Description |
|----------|--------|-------------|
| `uint8`  | `role` | 0 PR, 1 PI |
| endpoint | `peer` | the other party's endpoint |

- R-4.1 Fields appear in the order given; trailing or missing bytes make
  the message malformed and the sender MUST be disconnected.
- R-4.2 An endpoint with `net` other than `IPV4` or `IPV6`, an `addr_len`
  that does not match `net`, or a `role` other than 0 or 1 is malformed.
- R-4.3 Both fields of `rendezvous` MUST have the same address family.
- R-4.4 A party MUST NOT send more than one `rendezvous` per connection. A
  coordinating party MUST NOT send more than one `punch` per connection.

### 5. Punch procedure

#### Validation

- R-5.1 On receiving `punch`, a node MUST ignore it, and MAY close the
  connection, if any of the following holds: `peer` is not globally
  routable, is one of the node's own addresses or candidates, or has port
  0; the node has no punch port for `peer`'s address family; a session
  with the same (punch port, `peer`) exists; the node has
  `MAX_ACTIVE_SESSIONS` (2) sessions; the node started `SESSIONS_PER_MIN`
  (4) sessions in the last minute; a session to the same address was
  started within `PER_IP_INTERVAL` (10 min); the role is PR and no inbound
  slot is free; the role is PI and no hole-punch outbound slot is free
  (section 8).
- R-5.2 Endpoints whose port the implementation treats as a "bad port" for
  outbound connections SHOULD be ignored.
- R-5.3 A PR MUST reserve one inbound slot for the session until it
  terminates.

#### Attempts

- R-5.4 On accepting a `punch`, the node immediately opens a punch-port
  socket and calls `connect()` on `peer`, with a deadline at the end of the
  window (`WINDOW_MS`, 15000 ms after the `punch` was received).
- R-5.5 If an attempt fails before the deadline (connection reset,
  unreachable, or any immediate error), the node MUST close the socket,
  wait `RETRY_MS` (1000 ms), and open a new attempt, until the deadline.
  The pending `connect()` itself retransmits SYNs; the node MUST NOT run
  more than one attempt at a time per session.
- R-5.6 A node MUST NOT exceed `SYN_RATE` (20 attempts per second) across
  all sessions.

#### Establishment

- R-5.7 The session's connection is the first socket whose remote endpoint
  equals `peer` exactly, obtained either by a completed `connect()` of
  this session or by `accept()` on the punch-port listener. Because both
  parties use fixed ports, at most one TCP connection can exist per
  session. A socket accepted on the punch-port listener that matches no
  session MUST be closed.
- R-5.8 On establishment the node stops the attempts. The PI immediately
  sends its BIP 324 initiator bytes. The PR sends nothing until BIP 324
  bytes arrive.
- R-5.9 The punched connection MUST use the BIP 324 v2 transport. A v1
  prefix on the connection is an error; the connection MUST be closed and
  no v1 fallback attempted.
- R-5.10 The ordinary `version`/`verack` handshake follows on the
  encrypted connection; the PI sends `version` first. The session is
  complete when the node has received `verack`.

#### Termination

- R-5.11 A session ends when its connection has completed `verack`
  (success) or when the window plus `GRACE_MS` (2000 ms) has elapsed
  without that (failure). On failure every socket of the session MUST be
  closed and the reserved slot released.
- R-5.12 No outcome is reported over the protocol. A coordinating party
  learns of success only indirectly; an advertiser that still has free
  slots simply remains available.

#### Timing and mapping liveness

- R-5.13 Both parties start on receipt of `punch`. A coordinator sends
  the two `punch` messages back to back, the one for the PR first.
- R-5.14 A coordinator MUST keep both coordination connections open for
  `WINDOW_MS + GRACE_MS` after sending `punch`. Each party MUST keep at
  least one outbound punch-port connection open for the same time, so that
  its NAT mapping survives; R-1.1 makes this true for any node with
  outbound peers.

### 6. Announcements: the `HOLEPUNCH` address type

This document reserves BIP 155 network ID `0x08`, enumeration
`HOLEPUNCH`. The `addr` field is:

| Type        | Name          | Description |
|-------------|---------------|-------------|
| `uint8`     | `coord_net`   | `IPV4` (1), `IPV6` (2), `TORV3` (4), or `I2P` (5) |
| `uint8[]`   | `coord_addr`  | coordinating party's address, 4, 16, 32, or 32 bytes |
| `uint16_be` | `coord_port`  | coordinating party's port; MUST be 0 for `I2P` |
| `uint8`     | `target_net`  | `IPV4` or `IPV6` |
| `uint8[]`   | `target_addr` | the advertiser's candidate address, 4 or 16 bytes |

The element's `port` field is the advertiser's candidate port, `services`
the advertiser's services (MUST include `NODE_P2P_V2`), and `time` the
announcement time. Valid `addr` lengths are 12, 24, 36, 40, and 52 bytes;
the field is parsed by network IDs, and length 24 occurs for both
(`IPV6`, `IPV4`) and (`IPV4`, `IPV6`).

A clearnet `coord_net` means Profile A: the coordinator is a third node.
An onion or I2P `coord_net` means Profile B: the coordinating endpoint
belongs to the advertiser itself.

- R-6.1 Receivers MUST reject elements with an invalid length, with a
  `coord_net` or `target_net` outside the sets above, or with a
  `target_addr` that is not globally routable.
- R-6.2 **No storage.** `HOLEPUNCH` elements MUST NOT be added to the
  address manager, returned in response to `getaddr`, or persisted.
  Receivers keep them in a bounded in-memory cache of at most `CACHE_MAX`
  (32) entries with at most `CACHE_PER_PEER` (4) from one source peer,
  expiring `CACHE_TTL` (10 min) after `time`.
- R-6.3 **Relay.** An element MAY be relayed to a small number of peers
  that sent `sendaddrv2`, only if `now - 10 min < time <= now + 10 min`.
  It MUST NOT be sent to peers that did not negotiate `sendaddrv2`.
- R-6.4 **Clearnet only for Profile B.** Elements with an onion or I2P
  `coord_net` MUST only be sent on connections to `IPV4` or `IPV6` peers
  not reached through a proxy, so the coordination identity never appears
  on the privacy network itself.
- R-6.5 **Self-announcement.** An advertiser announces only while it has
  at least one free inbound slot, a valid candidate (R-2.2), and, in
  Profile A, an open connection to the named coordinator with
  `ADVERTISED` and `PUNCHPORT` set; at most once per `ANNOUNCE_INTERVAL`
  (10 min) per peer.
- R-6.6 Elements count against the receiving peer's address rate limit as
  one address each.

### 7. Connector behaviour

- R-7.1 A connector chooses targets only from its cache. An entry is
  eligible if `target_addr` and, in Profile A, `coord_addr` pass the
  connector's address-group diversity rules against its existing outbound
  peers, where a coordinator and every target announced through it count
  as one group[^one-group], and if the connector has a candidate in
  `target_net`'s family.
- R-7.2 A connector MUST NOT start more than one coordination attempt per
  `HP_ATTEMPT_INTERVAL` (5 min) and MUST drop a cache entry after one
  attempt, whatever its outcome.
- R-7.3 Profile A: the connector opens an outbound connection to
  `coord_addr:coord_port` from a punch-port socket with `PUNCHPORT` set,
  waits for the feature exchange, sends `rendezvous`, and closes the connection
  if no `punch` arrives within `COORD_TIMEOUT_MS` (30000 ms). Profile B:
  the same over Tor (or I2P) to `coord_addr`, with stream isolation.
- R-7.4 **Anti-redirection.** After the session completes, the connector
  MUST verify that the connection's remote endpoint equals the
  announcement's target and MUST close it otherwise.

### 8. Classification and slots

- R-8.1 In a session requested by the connector (Profile A targeted
  rendezvous, Profile B), the connector is PI and accounts the connection
  as a **hole-punch outbound**, a slot in addition to its ordinary
  automatic outbound slots. A node MUST NOT hold more than
  `HP_OUTBOUND_MAX` (1) such connections, MUST NOT use them as anchors,
  and MUST NOT count them when deciding whether its outbound connectivity
  is diverse enough to record address manager failures[^extra-slot].
  The advertiser accounts the connection as inbound.
- R-8.2 In a session created by a coordinator without a request (pool and
  handoff), both parties account the connection as inbound; the PI role
  only determines who starts the handshake.

### 9. Invariants

| ID | Invariant | Test shape |
|----|-----------|------------|
| I-1 | Each session has exactly one PI. The PI sends the first bytes (BIP 324 key, then `version`); the PR sends nothing before receiving BIP 324 bytes. | Force roles on two nodes; capture first bytes on the wire. |
| I-2 | A session is keyed by (punch port, peer endpoint) and has at most one connection, whose remote endpoint equals `peer` exactly. A socket accepted on the punch port that matches no session is closed. | Connect to the punch port from an unexpected endpoint; assert close. |
| I-3 | Every non-proxied clearnet outbound connection, every punch attempt, and the listener of one family share the punch port. | Inspect local ports of all sockets. |
| I-4 | Connect attempts go only to the `peer` of an accepted `punch` that is routable, not local, not the node's own address, same family; one attempt at a time per session; at most `WINDOW_MS / RETRY_MS + 1` attempts per session. | Feed invalid `punch`; count SYNs with a socket mock. |
| I-5 | At most `MAX_ACTIVE_SESSIONS` concurrent, `SESSIONS_PER_MIN` per minute, one per remote address per `PER_IP_INTERVAL`, `SYN_RATE` attempts per second. | Flood `punch`; assert ignores. |
| I-6 | Every session ends within `WINDOW_MS + GRACE_MS` in success or failure and releases every socket except the session connection and the reserved slot. | Drive sessions to both outcomes; compare socket counts. |
| I-7 | `HOLEPUNCH` elements never enter the address manager, `getaddr` responses, or persisted files, and are not relayed outside the time window. | Send elements; query address manager and `getaddr`; restart. |
| I-8 | A hole-punch outbound is kept only if its remote endpoint equals the announcement target and passes diversity; at most `HP_OUTBOUND_MAX` exist; none is an anchor. | Coordinator supplies a different `peer`; assert close. |
| I-9 | Punched connections use BIP 324 without v1 fallback; both parties advertise `NODE_P2P_V2`. | Send v1 `version` on a punched connection; assert close. |
| I-10 | A node announces only while two observers in distinct address groups agree on its endpoint (R-2.2) and it holds a free inbound slot; a PR reserves one slot per session. | Give conflicting reports; assert no announcement. |
| I-11 | A coordinator never relays application bytes, keeps both coordination connections open `WINDOW_MS + GRACE_MS` after `punch`, sends at most one `punch` per connection, and never pairs parties sharing an address. | Coordinator unit tests. |
| I-12 | The Profile B coordination service uses a key not used for anything else, rotates it at least every `ONION_ROTATE_H` (24 h), is never advertised through local address discovery or `getaddr`, and its announcements leave only on clearnet connections. | Compare onion ids; assert no element on onion peers. |

### 10. Limits

| Name | Default | Used in |
|------|---------|---------|
| punch port | default P2P port + 2 | section 1 |
| `WINDOW_MS` | 15000 | R-5.4 |
| `RETRY_MS` | 1000 | R-5.5 |
| `GRACE_MS` | 2000 | R-5.11 |
| `SYN_RATE` | 20 / s | R-5.6 |
| `MAX_ACTIVE_SESSIONS` | 2 | R-5.1 |
| `SESSIONS_PER_MIN` | 4 | R-5.1 |
| `PER_IP_INTERVAL` | 10 min | R-5.1 |
| `COORD_TIMEOUT_MS` | 30000 | R-7.3, R-11.3 |
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

- R-11.1 A coordinator keeps, for each connected peer with `PUNCHPORT`
  set, the endpoint it observed. It MUST only use observed endpoints, never
  the `requester` field of `rendezvous`, for peers that set `PUNCHPORT`.
- R-11.2 On `rendezvous` from a connected peer B, the coordinator looks for a
  connected peer A with `ADVERTISED` and `PUNCHPORT` whose observed
  endpoint equals `target`. If there is none, if A is already in a session,
  if A and B share an address, if B's endpoint is not in `target`'s
  family, or if more than `SESSIONS_PER_MIN` requests named A in the last
  minute, the coordinator MUST NOT send `punch` and MAY close B's
  connection. B gives up after `COORD_TIMEOUT_MS`.
- R-11.3 Otherwise the coordinator sends `punch(role=PR, peer=B's
  observed endpoint)` to A and `punch(role=PI, peer=A's observed
  endpoint)` to B, in that order, and applies R-5.14.
- R-11.4 A coordinator MUST NOT create more than `MAX_ACTIVE_SESSIONS`
  sessions involving the same peer at once and MUST NOT process more than
  one `rendezvous` per connection.

#### A.1 Targeted rendezvous (REQUIRED for Profile A)

```
 A (advertiser)                 C (coordinator)                B (connector)
 -- outbound from punch port, feature(ADVERTISED|PUNCHPORT) -->
 ... A announces HOLEPUNCH(coord=C, target=A's candidate) on the network ...
                                                    cache entry chosen
                                  <-- outbound from punch port, feature(PUNCHPORT) --
                                  <-- rendezvous(target=A cand, requester=B cand) ---------
 <-- punch(PR, peer=B obs) --   -- punch(PI, peer=A obs) ------------------------>
            ====== simultaneous open A:punch <-> B:punch ======
            <====== BIP 324 (B initiates), version/verack ======
```

- R-11.5 A announces `coord_*` set to the address it used to connect to C
  and `target_*` set to its candidate; it MUST keep the connection to C
  open while the announcement is valid (R-6.5).
- R-11.6 B accounts the connection per R-8.1 and applies R-7.4.

#### A.2 Matchmaking pool (OPTIONAL)

- R-11.7 Peers with `POOL_OK` and `PUNCHPORT` form the coordinator's
  pool. The coordinator MAY pair two members whose observed addresses
  differ, preferring different address groups, at most once per
  `PER_IP_INTERVAL` for the same pair.
- R-11.8 The PI is the member whose observed endpoint, serialized as an
  endpoint, is lexicographically smaller. Both members account the
  connection per R-8.2.

#### A.3 Handoff instead of eviction (OPTIONAL)

- R-11.9 When a coordinator's inbound capacity is exhausted and it would
  evict peer X to admit peer Y, it MAY instead, if both have `HANDOFF_OK`
  and `PUNCHPORT`, have completed `verack`, do not share an address, and
  have no elevated permissions, send `punch` to both with roles per
  R-11.8, keep both connected for `WINDOW_MS + GRACE_MS`, and then
  disconnect X. Both account the connection per R-8.2.

#### Trust considerations for coordinators

The coordinator learns that A and B were paired and when. It can refuse to
pair and can send a wrong `peer`, which costs the recipient at most one
session's attempts (R-5.5, R-5.6) and is caught by R-7.4 on the
connector side. It cannot read or modify the punched connection. Pool and
handoff sessions are inbound on both sides and do not influence outbound
selection; targeted sessions occupy one extra slot (R-8.1) and the
coordinator with its targets counts as one group (R-7.1).

### 12. Profile B: self-coordinated over Tor

The advertiser runs a Tor v3 onion service dedicated to this protocol and
acts as its own coordinator. I2P endpoints are permitted through
`coord_net` = `I2P` with the same rules; I2P specifics are out of scope.

- R-12.1 The coordination onion service MUST use a key not used for any
  other purpose, MUST NOT be added to the node's local address list or
  returned via `getaddr`, and MUST be replaced by a fresh key at least
  every `ONION_ROTATE_H` (24 h)[^rotation]. Its virtual port is the
  network's default P2P port. Implementations SHOULD terminate it on a
  distinct local bind address so that inbound connections on it are
  recognisable as coordination connections.
- R-12.2 Connections accepted on the coordination endpoint carry only
  `version`, `verack`, `feature`, `ping`, `pong`, `rendezvous`, and `punch` messages; any
  other message MUST result in disconnect. The advertiser MUST NOT accept
  more than `COORD_INBOUND_MAX` (8) such connections and MUST close one
  that has not completed `verack` and the feature exchange within
  `COORD_TIMEOUT_MS`.
- R-12.3 The advertiser announces `coord_*` set to the onion service and
  the default port and `target_*` set to its candidate, subject to R-6.4
  and R-6.5.

```
 A (advertiser, own onion coordination endpoint)             B (connector)
 ... A announces HOLEPUNCH(coord=onion, target=A cand) on clearnet ...
                                                       cache entry chosen
 <-------- Tor connection (stream isolation), feature exchange -----------
 <-------- rendezvous(target=A cand, requester=B cand) ------------------------
 --------- punch(PI, peer=B cand) ------------------------------------->
            ====== simultaneous open A:punch <-> B:punch ======
            <====== BIP 324 (B initiates), version/verack ======
 (A closes the coordination connection after the window)
```

- R-12.4 On `rendezvous`, A checks that `target` equals its current candidate
  (R-2.2), that `requester` passes R-5.1 and does not share A's address,
  and the limits of R-5.1. If any check fails A MUST NOT answer and MAY
  close the connection.
- R-12.5 Otherwise A sends `punch(role=PI, peer=requester)`, starts its
  own attempts as PR (R-5.4), and closes the coordination connection after
  `WINDOW_MS + GRACE_MS`. A MUST always assign PI to the connector.
- R-12.6 B accounts the connection per R-8.1 and applies R-7.4.

#### Privacy considerations for Profile B

An announcement links an onion identity to a clearnet endpoint by design.
R-12.1 and R-6.4 keep that identity separate from everything else and
short-lived. B learns that A is unreachable and A's clearnet endpoint; A
learns B's clearnet endpoint but not which Tor client connected. No third
party learns of the pairing.

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
peer, upgraded or not, serves as observer.

[^bind-all]: Binding every outbound connection to the punch port turns
every peer into an observer, keeps the NAT mapping alive as long as the
node has any outbound connection, and removes any need for dedicated probe
connections. An observer learns that the node uses a fixed source port,
which reveals nothing beyond the node's address that it already sees. Two
connections to the same remote endpoint from one punch port are
impossible, which never happens in normal operation.

[^one-group]: Proposed in the Delving thread: if the connector picks a
coordinator and then any target announced through it, the coordinator's
operator decides which target the connector ends up with; treating the set
as one group keeps the number of independent parties a connector depends
on unchanged.

[^extra-slot]: Using one of the ordinary automatic outbound slots would let
a coordinator or an announcement flood influence the selection of ordinary
peers; a dedicated extra slot bounds the influence to one connection.

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
four per minute per node, one per remote address per ten minutes, twenty
attempts per second globally. Endpoints must be routable and not local;
bad ports are avoided.

**Sybil and eclipse through coordinators.** Pool and handoff sessions are
inbound on both sides. Targeted sessions use one extra outbound slot, must
pass diversity rules with the coordinator and its targets as one group,
and the connector verifies the remote endpoint. An attacker flooding
announcements can obtain at most that one slot from a victim, at the cost
of one coordination attempt per five minutes per victim.

**Announcement spam.** `HOLEPUNCH` elements pass through the existing
address rate limits, are capped per source peer and in total in a
short-lived cache, are relayed only while fresh, and never reach
persistent storage.

**Request triggering.** In Profile B a request causes no new outbound
connection; A's candidate comes from its existing peers. The number of
concurrent coordination connections and requests per minute is capped.

**Lying observers.** An observer can report any address in `addr_recv`.
Only agreement between two observers in distinct address groups produces a
candidate, and in Profile A the coordinator uses its own observation. A
wrong candidate wastes one session's attempts at most.

**Coordinator exhaustion.** Coordinators keep no state beyond the observed
endpoint of connected peers, limit requests per target and per connection,
and close idle coordination connections.

**Linkability.** Profile A reveals the pairing to the coordinator and the
advertiser's NAT status to the connector. Profile B reveals the
advertiser's clearnet endpoint to anyone who sees the announcement, by
design; R-12.1 and R-6.4 keep that identity separate from everything else.

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

* 0.2.0 (2026-10-10): dedicated punch port, outbound connections bound to
  it, EIM-only scope, two messages instead of seven, no session ids,
  tokens, short IDs, or service bit; messages named `rendezvous` and
  `punch`.
* 0.1.0 (2026-10-10): initial draft with both coordination profiles.

## Appendix: state machines

See [`bip-tcp-holepunch/state-machines.md`](bip-tcp-holepunch/state-machines.md)
for the session, advertiser, connector, and coordinator state tables.
