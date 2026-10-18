```
  BIP: ?
  Layer: Peer Services
  Title: Coordinator-less TCP Hole Punching for Peer Connections
  Authors: TBD
  Status: Draft
  Type: Specification
  Assigned: ?
  License: BSD-2-Clause
  Discussion: 2026-10-16: https://delvingbitcoin.org/t/tcp-hole-punching-for-bitcoin-nodes-behind-home-nats/2497/22
  Version: 0.4.9
  Requires: 155, 324, 434
```

## Abstract

Two nodes behind home NATs can connect to each other if both send a SYN
to the other at about the same time and both NATs give connections from
one local port a stable external port. This document lets nodes do that
without anyone telling them whom to connect to or when.

A node keeps one fixed local port for this protocol, the *punch port*,
connects from it to a few reachable nodes that act as *boards*, and
learns its external address from what the boards echo back in
`version`. It announces that address together with a short-lived public
key to those boards. A board checks
that the announced address is the one it sees on the connection, keeps
the announcement for as long as the connection lasts, and passes it to
its other visitors; it never chooses a pair or a time. Every new block
starts a *round*: for each announcement it holds, a node derives a *pair
value* from the ECDH shared secret of the two keys, the block hash, and
the two endpoints, and connects from its punch port to the few
announcers with the lowest values. Both nodes of a pair derive the same
value, so they tend to choose each other in the same round, and because
the block did not exist when the keys were published, nobody can choose
a key in order to be picked. No message is exchanged before the SYNs
cross.

## Copyright

This BIP is licensed under the BSD-2-Clause License. Auxiliary code in
`bip-tcp-holepunch-coordinatorless/` is additionally licensed under the
MIT License.

## Motivation

Most Bitcoin nodes on home connections sit behind a NAT and never accept
an inbound connection. They use inbound slots of reachable nodes and
offer none, and automatic port mapping has not changed that noticeably.
TCP hole punching lets two such nodes connect directly. Roughly two
thirds of home IPv4 NATs behave the way it needs, and IPv6 at home
usually means no NAT and only a stateful firewall, which the same
procedure passes[^numbers].

Hole punching needs two things: each node must know the other's external
address and port, and both must connect at about the same moment. Other
designs take both from a coordinator, a third node or a Tor service that
introduces the two. The coordinator learns who connects to
whom, can refuse, and is one more thing to run. This document takes the
moment from the next block, which every node sees within seconds of
every other, and the address from a board: a reachable node that holds
announcements, checks each one against the connection it came in on,
and otherwise does nothing. Ordinary address relay was considered for
the addresses and rejected[^why-not-relay]; a board can check what relay
cannot[^boards].

Connections made this way are extra, best-effort connections for nodes
that have none to offer today. Nothing about ordinary connections
changes.

## Scope

This document covers pairs of nodes whose NAT or firewall maps every
outbound connection from one local port to the same external port
(endpoint-independent mapping in the sense of RFC 4787). A node with a
stateful firewall and no NAT qualifies. Symmetric NATs, carrier-grade
NAT, and most mobile networks do not; a node that detects such a mapping
does not take part. How the NAT filters inbound packets does not matter,
because each side sends to the other before the other's SYN arrives.

Taking part is opt-in, for visitors and for boards. A node that does not
opt in is unaffected. A node in initial block download holds no rounds.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

Integers are little-endian unless the name ends in `_be`. `CompactSize`
is the P2P protocol's variable-length integer, minimally encoded.

**Endpoint.** An address and port, encoded as a BIP 155 address element
without `time` and `services`:

| Type          | Name       | Description |
|---------------|------------|-------------|
| `uint8`       | `net`      | `IPV4` (1) or `IPV6` (2) |
| `CompactSize` | `addr_len` | 4 or 16 |
| `uint8[]`     | `addr`     | address bytes |
| `uint16_be`   | `port`     | port, big-endian as in BIP 155 |

**Punch port.** One local TCP port per address family, used for board
connections and for punching, and for nothing else. It is chosen at random
from 49152 to 65535 when the node starts, skipping ports the
implementation treats as bad, is configurable, and never changes while
the node runs[^punch-port].

**Punch socket.** A TCP socket bound to the punch port with
`SO_REUSEADDR` and `SO_REUSEPORT` set before binding.

**Report.** The `addr_recv` field of a peer's `version` message: the
node's address and port as that peer sees them. A report counts only on
a connection the node opened from a punch socket without a proxy, or on
the connection a session produced, and only once the version handshake
on it is complete; the peers of those connections are the *reporting
peers*. Today they are the node's boards and the peers it punched to,
but what makes a report meaningful is the local port the connection was
made from, not what the peer is.

**External address.** For one address family, the endpoint that at least
two current reporting peers in different network groups report, as long
as no two reporting peers in different groups report another one.

**Network group.** The grouping the implementation uses for outbound
peer diversity, such as /16 for IPv4, /32 for IPv6, or autonomous
systems.

**Board.** A reachable node that accepts board connections, stores the
announcements it can verify against those connections, and sends them to
its other visitors (section 5).

**Visitor, board connection.** A participant that connects to a board
from its punch port, and that connection. A board connection carries
nothing but this protocol (R-3.5).

**Source group.** The network group of the board an element came from,
taken from the board's address.

**Key.** A secp256k1 key pair the node holds for this protocol, one per
address family it announces: a secret `p` and `P = p·G`, with `P`
serialized as a 33-byte compressed point.

**Entry.** A stored announcement: its endpoint, its public key, the
element's `time`, the local time the node first received that endpoint
and key together (`received_at`), the local time it last received them
(`last_seen`), the shared secret (R-4.4), and the source group.

**Pair value.** A 256-bit value derived from two nodes' keys, a block
hash, and their two endpoints (R-4.5). The two nodes compute the same
value; nobody else can.

**Round.** The evaluation of the table that one new block triggers
(section 7).

**Roles.** Each session has an *initiator* and a *responder* in the sense
of BIP 324: the initiator sends the first bytes. The role comes from the
pair value (R-4.7), never from whether the socket came out of `connect()`
or `accept()`.

**Session.** The state of one attempt, keyed by (punch port, peer
endpoint), started by a pick (R-7.4).

## Specification

### 1. Sockets

- R-1.1 Board connections (R-5.2) and punch attempts MUST be made from a
  punch socket of their family. Ordinary outbound connections are not
  affected by this protocol: their source ports, selection, and
  accounting stay as they are[^punch-port].
- R-1.2 The node MUST listen on each punch port. A connection accepted
  there is a punched connection and nothing else.
- R-1.3 Punch attempts are non-blocking connects from punch sockets. An
  attempt that is superseded MUST be closed.
- R-1.4 IPv4-mapped IPv6 addresses MUST NOT appear in endpoints, reports,
  announcements, or connect targets. Punch sockets SHOULD be bound to a
  stable local address; IPv6 temporary addresses make reports disagree.

### 2. External address

- R-2.1 A report MUST be ignored unless the connection it arrived on was
  opened by this node from a punch socket, or is the connection a session
  produced, and the version handshake on that connection is complete. A
  report from a proxied connection, with an address that is not globally
  routable, or with port 0 MUST be ignored as well. An inbound connection
  that merely arrives on the punch port is not a reporter[^who-reports].
- R-2.2 The node has an external address for a family when at least two
  current reporting peers in different network groups report the same
  endpoint. A single dissenting report changes nothing.
- R-2.3 If two such sets report different endpoints, the node's mapping is
  not endpoint-independent or it has several addresses. It then has no
  external address for that family and MUST NOT announce until R-2.2
  yields one endpoint again.
- R-2.4 Losing the external address stops new announcements and new picks
  for that family. Sessions already running continue.
- R-2.5 On test networks where all nodes share a host, an implementation
  MAY waive routability (R-2.1, R-5.1, R-7.3), treat every peer as its
  own network group, and compare full endpoints instead of addresses
  where this document compares addresses (`BOARD_IP_CAP` in R-5.5 and
  R-5.7, the own-address exclusion in R-7.3), since every node there has
  the same address. Treating every peer as its own network group covers
  every use of the grouping, including the source groups of section 6 and
  the per-group session budget of R-7.3, which would otherwise collapse
  to one group.

### 3. Signalling

- R-3.1 Support is signalled per connection with a BIP 434 `feature`
  message. The `featureid` is `https://delvingbitcoin.org/t/2497/22`
  until a BIP number is assigned, then `BIP<n>`. The `featuredata` is:

  | Type     | Name      | Description |
  |----------|-----------|-------------|
  | `uint8`  | `version` | highest version the sender supports; 0 for this document |
  | `uint32` | `flags`   | see below; unknown bits are ignored |

  | Bit | Name      | Meaning |
  |-----|-----------|---------|
  | 0   | `BOARD`   | the sender acts as a board |
  | 1   | `VISITOR` | the sender opened this connection as a board connection and will announce on it |

- R-3.2 The version in use on a connection is the lower of the two
  announced. A node that supports version N MUST support every lower
  defined version. Only version 0 is defined[^min-version].
- R-3.3 Participating nodes MUST advertise `NODE_P2P_V2`. A board also
  advertises the service bit `NODE_HOLEPUNCH_BOARD`, bit 24 while the
  protocol is experimental, so that visitors can find boards in their
  address manager[^service-bit].
- R-3.4 The feature SHOULD NOT be sent on a connection that closes right
  after the handshake, such as a feeler: it would only tell one more
  node that the sender takes part.
- R-3.5 A connection is a *board connection* once the visitor has sent
  the feature with `VISITOR` and the board has sent it with `BOARD`.
  Before `verack` both sides send what their version handshake sends,
  including the `feature` message; from `verack` on, both sides send
  only `ping`, `pong`, and `addrv2` messages consisting of `PUNCHKEY`
  elements, and either side MUST disconnect on any other message. The
  visitor sends `version` with transaction relay disabled. If either
  flag is missing after the feature exchange, the visitor closes the
  connection.
- R-3.6 This document defines no new message. The only new wire element
  is the `PUNCHKEY` address type. `PUNCHKEY` elements MUST NOT be sent on
  any connection other than a board connection, and a node that receives
  one on any other connection MUST disconnect.

### 4. Keys and the pair value

- R-4.1 When it starts, a participating node generates a secp256k1 key
  pair from fresh randomness for each address family it may announce: a
  uniformly random secret `p` in `[1, n-1]` and `P = p·G`. A key MUST NOT
  be derived from or shared with any other key, including the node's key
  for the other family, and is used for nothing but this protocol.
- R-4.2 A node has one current key per address family. The IPv4 and IPv6
  keys of one node are independent, and nothing in the protocol links
  them[^key-per-family].
- R-4.3 A family's key MUST be replaced when that family's external
  address changes, so that a new address is never announced under a key
  that was seen with an old one, and at least every `KEY_ROTATE_H`
  (24 h), at a time not aligned across nodes and not aligned with the
  node's other family[^rotation]. After replacement the node uses the new
  key only and SHOULD announce that family again promptly (R-5.3).
  Replacing a key changes every shared secret of that family, so the node
  MUST recompute the shared secret of each stored entry of that family
  with the new key, keeping each entry's `received_at` (R-6.1); it MAY
  then discard the old key. Until the new announcement reaches a peer,
  that peer still holds the old public key and computes the old secret, so
  the two sides disagree for as long as the announcement takes to
  arrive[^rotation-secret].
- R-4.4 The **shared secret** between the node and an entry is `x`, the x
  coordinate of `p · P_entry` as 32 bytes big-endian, where `p` is the
  node's key for the entry's address family. The other node computes
  `p_entry · P` with its own key for that family and gets the same `x`.
  If the product is the point at infinity the entry MUST be ignored.
- R-4.5 The **pair value** of an entry for a block is

  ```
  pair = TaggedHash("tcp-holepunch/pair",
                    x || block_hash || min(ep_own, ep_entry) || max(ep_own, ep_entry))
  ```

  with `TaggedHash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)` as
  in BIP 340; `block_hash` the block's header hash in the byte order of
  the `prev_block` field of a header, which is the reverse of the hex
  shown by explorers; `ep_own` the node's external endpoint for the
  entry's family and `ep_entry` the entry's endpoint, each encoded as in
  Terminology; and `min` and `max` the lexicographic order of those
  encodings[^endpoints-in-hash]. The other node has the same two
  endpoints and gets the same value.
- R-4.6 Pair values are **ranked** as 256-bit unsigned integers, first
  byte most significant, lower first.
- R-4.7 The **role** follows from the pair value: let `bit` be the lowest
  bit of the last byte of `pair`. The node with the lexicographically
  smaller compressed public key is the initiator if `bit` is 0 and the
  responder if `bit` is 1; the other node takes the other
  role[^coin-flip].

### 5. Boards

This document reserves BIP 155 network ID `0x09`, enumeration
`PUNCHKEY`, for announcements. The `addr` field is:

| Type        | Name     | Description |
|-------------|----------|-------------|
| `uint8`     | `net`    | `IPV4` (1) or `IPV6` (2) |
| `uint8[]`   | `addr`   | the announcer's external address, 4 or 16 bytes |
| `uint8[33]` | `pubkey` | the announcer's current key for that family, compressed |

The element's `port` is the external port and `services` the announcer's
services (MUST include `NODE_P2P_V2`). The `time` field carries no
meaning in this protocol: a visitor writes the current time, a board
writes the time it received the element, and receivers do not act on
it[^time]. Valid `addr` lengths are 38 and 50 bytes.

- R-5.1 A receiver MUST reject an element whose length is neither 38 nor
  50 bytes or does not match its `net` (38 for `IPV4`, 50 for `IPV6`), a
  `net` other than `IPV4` or `IPV6`, an `addr` that is not globally
  routable, a `port` of 0, a `pubkey` that is not a valid compressed
  point (prefix other than `0x02` or `0x03`, x coordinate not below the
  field size, or x not on the curve), or `services` without
  `NODE_P2P_V2`. A rejected element is ignored; rejection alone is no
  reason to disconnect.

#### Visitors

- R-5.2 A participant keeps `BOARDS` (2) board connections for each
  address family it takes part in, to boards in distinct network groups,
  chosen uniformly at random from reachable addresses in its address
  manager that advertise `NODE_HOLEPUNCH_BOARD` and `NODE_P2P_V2` and
  that it is not otherwise connected to. It opens each from a punch
  socket (R-1.1), so
  that the board observes its mapped endpoint and reports it; the boards
  are the reporting peers that R-2.2 needs. It replaces a board
  connection `BOARD_ROTATE_H` (6 h) after opening it, at a time not
  aligned across nodes, and whenever it closes[^standing]. It also
  replaces one of them when the boards' reports disagree (R-2.3), and
  replaces a connection the board closes before serving anything, as a
  board does when it refuses a visitor (R-5.5), or that yields no
  acknowledgement (R-5.3). Of those, only a disagreeing report and a
  missing acknowledgement count towards the pause below: they say
  something about this node, the others say something about the address.
  `NODE_HOLEPUNCH_BOARD` is an unauthenticated advertisement, so a
  candidate that cannot be reached, closes before the handshake is
  complete, or never sends `BOARD` is only a bad address; a node MUST NOT
  count it and SHOULD NOT pick that address again for
  `BOARD_BACKOFF`[^unauthenticated-bit]. After `BOARD_FAIL_MAX` (4)
  counting outcomes in a row for one family it stops for `BOARD_BACKOFF`
  (1 h)[^backoff]; an acknowledgement clears the count.
- R-5.3 On a board connection, after the feature exchange, the visitor
  sends one element: its external address for the connection's family
  (R-2.2) and that family's key. It sends a new element on that
  connection whenever the key or the external address changes, and
  nothing else about itself. The board answers every element with its
  live entries (R-5.8); if that answer does not contain the visitor's own
  entry, or no answer arrives within `BOARD_ACK` (60 s), the board did
  not store it, usually because it saw a different endpoint, and the
  visitor replaces the connection with one to a different board[^ack]. A
  visitor announces only while it has a free hole-punch outbound slot
  (section 9) or a free inbound slot, counting slots reserved by sessions
  as used; with neither free it closes its board connections and reopens
  them when a slot frees[^both-announce]. It announces only while it is
  close to the tip in the sense of R-7.1, since a node that is catching
  up holds no rounds and so cannot punch back to anyone who picks it.
- R-5.4 Elements a board sends on a board connection go to the table of
  section 6 with the board's network group as the source group. A
  visitor MUST NOT forward elements to anyone.

#### Boards

- R-5.5 A node that sets `BOARD` accepts board connections into a pool of
  at most `BOARD_VISITORS_MAX` (32), kept apart from its ordinary inbound
  limit, with at most `BOARD_PER_GROUP` (4) visitors from one network
  group and `BOARD_IP_CAP` (1) from one address. Until the visitor's
  feature arrives the board cannot tell it from an ordinary inbound
  connection and MAY count it as one. A connection beyond any
  of these limits is closed after the handshake without being served
  anything, except that when the pool is full a board MAY instead close
  the longest-connected visitor from the most represented network group
  to admit one from a less represented group.
- R-5.6 **Verification.** A board stores an element from a visitor only
  if it passes R-5.1 and its `net`, `addr`, and `port` equal the remote
  endpoint of the board connection it arrived on. Any other element is
  ignored. A board holds one entry per board connection; a later element
  on the same connection replaces it. The entry's `time` is the time the
  board received the element.
- R-5.7 **Lifetime.** An entry lives while its connection is open and
  `BOARD_GRACE` (10 min) after it closes. A board holds at most
  `BOARD_IP_CAP` (1) entry per address, counting an entry in its grace
  period; a verified element from an address whose entry is in its grace
  period replaces that entry[^ip-cap]. Since R-5.5 admits one connection
  per address, an entry with an open connection is never displaced.
- R-5.8 **Serving.** In answer to an element from a visitor, the board
  sends that visitor every entry whose connection is open, including the
  visitor's own entry if it stored it. When it stores or replaces an
  entry, it sends that element to every other visitor. Every
  `BOARD_REFRESH` (30 min) it sends every entry whose connection is open
  to every visitor again, each visitor's own included[^refresh]. Entries
  in their grace period are kept for the per-address cap only and are not
  sent. Elements are sent in `addrv2` messages with the `time` the board
  recorded. A board MUST NOT send `PUNCHKEY` elements on any other
  connection and MUST NOT pass elements between boards.
- R-5.9 A board MUST NOT add `PUNCHKEY` elements to its address manager,
  persist them, or include them in `getaddr` responses. Its entries exist
  only in memory and only for connections of its current run.
- R-5.10 **Rate.** A node MUST NOT process more than `PUNCHKEY_PER_HOUR`
  (240) elements from one peer in any hour, counting every element
  received whether or not it is accepted. Further elements from that peer
  in that hour are ignored, which is not by itself a protocol violation,
  and a node SHOULD NOT send a peer more than that[^rate-limit]. A board
  connection carries no address relay, so the general address rate limit
  has nothing to apply to there.
- R-5.11 A node does not store elements that carry one of its own public
  keys or one of its own external addresses. On a board connection, its
  own entry in the board's answer is the acknowledgement of R-5.3, nothing
  more.

### 6. The table

The table is organised by the board an element came from. Nothing in it
is keyed by a value the announcer chooses, and every entry from an honest
board names an endpoint that board saw connect[^source-cap].

- R-6.1 Entries are identified by (endpoint, `pubkey`). The shared secret
  is computed when the entry is stored, with the node's current key for
  the entry's family, and again whenever that key is replaced (R-4.3).
  Receiving an element for a stored (endpoint, `pubkey`) refreshes it:
  `last_seen` becomes the current time and `received_at` stays. An
  element from a board whose address equals that of an entry from the
  same board but whose `pubkey` differs replaces that entry: the old
  entry is removed and the new one stored with a new `received_at`, since
  the board holds one entry per address and the node behind it has
  changed its key or its port[^replace]. An element carrying a stored
  `pubkey` under a different address never replaces anything; it is a
  distinct entry.
- R-6.2 A node keeps at most `SOURCE_CAP` (64) entries per source group.
  To store a new entry for a full group it evicts an expired entry of that
  group if there is one, otherwise one chosen uniformly at
  random[^random-eviction]. A refresh evicts nothing.
- R-6.3 A node keeps at most `TABLE_MAX` (1024) entries in total. To store
  a new entry in a full table it evicts an expired entry if there is one,
  otherwise one chosen uniformly at random from the source group with the
  most entries.
- R-6.4 An entry expires `ENTRY_TTL` (1 h) after its
  `last_seen`[^last-seen]. Expired entries take no part in rounds and MAY
  be removed at any time.
- R-6.5 An entry is removed when a round picks it (R-7.6).
- R-6.6 The table is not persisted; a restart begins with an empty table.

### 7. Rounds

- R-7.1 A round starts when the node's active chain tip changes to a
  block `B` at a greater height than before, the node is not in initial
  block download, and its blocks are at most `TIP_LAG` (2) behind the
  best header it knows[^near-tip]. A tip change that does not increase
  the height, such as a reorganisation to a chain of equal length, holds
  no round[^reorg]. Each block hash triggers at most one round. The round
  starts at the time of the tip change, and the node remembers that time
  for each of its recent tips; blocks connected in one batch share the
  batch's time[^block-trigger].
- R-7.2 An entry takes part in the round for `B` only if its
  `received_at` is earlier than the time the tip reached `B`'s
  parent[^parent]. If the tip reached `B`'s parent before the node's
  current run, no entry takes part.
- R-7.3 An eligible entry is a *candidate* if all of the following hold:
  - it has not expired, and the node has a punch port and an external
    address for its address family;
  - its endpoint is globally routable, its address is not one of the
    node's own addresses or the address of one of its external
    endpoints[^same-nat], and its port is not one the implementation
    treats as a bad port;
  - the node has no connection and no session to the endpoint;
  - as initiator, its services include every service the node requires
    of an ordinary outbound peer[^services];
  - fewer than `GROUP_SESSIONS_PER_HOUR` (4) sessions to addresses in its
    network group started in the last hour;
  - with the role from R-4.7 for this round: as initiator, the hole-punch
    outbound slot is free and the endpoint passes the node's outbound
    network-group diversity rules; as responder, an inbound slot is free.
    Reserved slots count as used.

  The address, port, and network group checked here are the announced
  ones. An honest board saw them connect; a lying board may invent them.
  Either way the node sends its SYN to exactly the endpoint it evaluated,
  so a false entry costs one session's attempts and nothing else.
- R-7.4 The node computes the pair value (R-4.5) of every candidate for
  `B`, sorts the candidates by it (R-4.6), and walks the list from the
  lowest value. It skips a candidate whose network group equals that of
  a candidate already taken this round, one whose source group equals
  that of two candidates already taken[^one-ticket], and one whose
  role's slot was reserved meanwhile. It stops after
  `PICKS_PER_ROUND` (3) picks, or earlier when another session would
  exceed `MAX_ACTIVE_SESSIONS` (6)[^ranking]. For each pick it reserves
  the slot the role needs until the session ends and starts a session
  (section 8) with the entry's endpoint and the round's start time. A
  node with neither a free hole-punch outbound slot nor a free inbound
  slot skips the round.
- R-7.5 No attempt is made outside a round, and no entry is attempted
  more than once per announcement.
- R-7.6 A picked entry is removed from the table whatever the outcome. It
  comes back only with a new announcement, which then waits for R-7.2
  again.

### 8. Punching

- R-8.1 On a pick the node opens a punch socket and calls `connect()` on
  the entry's endpoint, with a deadline `WINDOW_MS` (120000 ms) after the
  session start. It leaves the attempt pending: the operating system
  retransmits the SYN, and the pending attempt keeps the NAT mapping
  towards the peer alive[^window]. At the deadline it MUST close a pending
  attempt and start no more, but keeps accepting a matching socket on the
  punch port until the session ends (R-8.7).
- R-8.2 If an attempt fails before the deadline, for any reason including
  the operating system giving up, the node MUST close the socket, wait
  `RETRY_MS` (1000 ms) doubled after each failure, and connect again. One
  attempt at a time per session; with these numbers at most seven.
- R-8.3 An attempt that fails because the 4-tuple is already in use is
  closed and not retried; the node waits for a matching socket from the
  listener until the session ends. Operating systems report this as
  `EADDRINUSE` or `EADDRNOTAVAIL`.
- R-8.4 The session's connection is the first socket whose remote endpoint
  equals the entry's endpoint, whether it came from `connect()` or from
  `accept()` on the punch port; with fixed ports on both sides there can
  be only one. A socket accepted on the punch port that matches no session
  is *held*: nothing is read from or written to it, it becomes the
  session's connection if a session for its endpoint starts within
  `HOLD_MS` (10000 ms), and it is closed otherwise. At most `HELD_MAX` (8)
  sockets are held; the oldest is closed to make room[^hold].
- R-8.5 On establishment the node stops its attempts. The initiator sends
  its BIP 324 initiator bytes at once. The responder sends nothing until
  bytes arrive; if its connection is closed before any byte arrived, the
  peer was not ready yet, the session goes on, and the responder resumes
  attempts under R-8.1 and R-8.2. A connection closed after bytes were
  exchanged ends the session as a failure.
- R-8.6 The connection MUST use the BIP 324 v2 transport. A v1 prefix
  MUST close it; there is no fallback. The usual `version`/`verack`
  handshake follows, the initiator sending `version` first.
- R-8.7 The session ends in success when `verack` has been received, or in
  failure `WINDOW_MS + GRACE_MS` (125000 ms) after the session start
  without it; handshake progress does not extend that deadline. On failure
  every socket of the session is closed and the reserved slot released.
  Nothing is reported to anyone, and nothing is retried until the peer
  announces again.
- R-8.8 Both nodes start their sessions when their own tip reaches `B`, so
  their start times differ by the difference in block propagation and
  validation, usually seconds. Because both attempts stay pending, the two
  SYNs only have to cross once anywhere in the overlap of the two windows;
  the first SYN to reach a NAT that has no mapping yet is dropped and
  retransmitted. No clock is involved. The board connections keep the
  mapping alive between sessions, and the pending attempt keeps it alive
  towards the peer.

### 9. Slots

- R-9.1 The initiator accounts the connection as a *hole-punch outbound*,
  one slot beyond its ordinary automatic outbound slots
  (`HP_OUTBOUND_MAX` = 1), never an anchor and not counted when deciding
  whether outbound connectivity is diverse enough to record address
  manager failures[^extra-slot]. The responder accounts it as inbound,
  with everything that implies, including transaction announcement
  delays and eviction. Board connections count as neither; they are
  limited-purpose connections outside both pools.

### 10. Invariants

| ID | Invariant | Test shape |
|----|-----------|------------|
| I-1 | Each session has exactly one initiator, given by the pair value; it sends the first bytes (BIP 324 key, then `version`), and the responder sends nothing before receiving BIP 324 bytes. | Two nodes with known keys and a chosen block; capture first bytes; swap in a block with the other role bit. |
| I-2 | A session is keyed by (punch port, peer endpoint) and has at most one connection, whose remote endpoint equals the entry's endpoint. An accepted socket that matches no session is held untouched for at most `HOLD_MS`, then closed unless a session for its endpoint started; at most `HELD_MAX` are held. | Connect to the punch port unexpectedly; assert silence and closure after `HOLD_MS`. Connect, then start a session for that endpoint; assert it uses the held socket. |
| I-3 | Every board connection, every punch attempt, and the listener of a family share the punch port; ordinary outbound connections do not use it. | Inspect local ports of all sockets. |
| I-4 | SYNs go only to endpoints of entries picked in a round: routable, not local, not the node's own address, same family, not a bad port; one attempt at a time; at most seven per session. | Feed elements with bad endpoints; count SYNs with a socket mock. |
| I-5 | Per round at most `PICKS_PER_ROUND` sessions start, at most two per source group and one per network group; at most `MAX_ACTIVE_SESSIONS` exist; at most `GROUP_SESSIONS_PER_HOUR` start per network group per hour. | Serve a table from one board and from several; connect blocks; count sessions per source and per group. |
| I-6 | Every session ends within `WINDOW_MS + GRACE_MS` in success or failure, releasing every socket but the connection and the reserved slot. | Drive sessions to both outcomes; compare socket counts. |
| I-7 | `PUNCHKEY` elements travel only on board connections, from a visitor to its board and from a board to its visitors; they never enter the address manager, `getaddr` responses, or persisted files, and no node forwards one it received; at most `PUNCHKEY_PER_HOUR` per peer are processed. | Send elements on an ordinary connection: assert disconnect. Query the address manager and `getaddr`. Exceed the rate. Restart. |
| I-8 | A hole-punch outbound exists only as the initiator side of a session with a picked entry that passed outbound diversity; at most `HP_OUTBOUND_MAX`; never an anchor. | Entry in an existing outbound's group: assert no initiator session. |
| I-9 | Punched connections use BIP 324 without v1 fallback; both nodes advertise `NODE_P2P_V2`. | Send a v1 `version` on a punched connection; assert close. |
| I-10 | Only a connection the node opened from a punch socket, or the connection a session produced, reports, and only once its handshake is complete; the node has an external address only while two reporting peers in different network groups agree and no second such set disagrees; it announces only with an external address, its current key, and a free slot of either kind; a pick reserves the slot its role needs. | Report on an ordinary outbound and on a connection accepted on the punch port: assert neither counts. A peer that sends `version` and no `verack`: assert no report. One dissenting report: address kept. Two agreeing dissenters: address dropped, no announcement. Both slots taken: board connections closed, no picks. |
| I-11 | No source group exceeds `SOURCE_CAP` and the table never exceeds `TABLE_MAX`; a full group evicts at random within itself, a full table evicts from its largest group, a refresh evicts nothing; an entry from one board is never displaced by another board's elements; an entry is replaced only by the board that served it, for the same address with a different key, and never by its key appearing under another address; a re-received entry keeps `received_at`; a picked entry is removed. | Serve many entries from one board; count that board's entries; check other boards' entries are untouched. Re-send a stored element; assert eligibility unchanged. Serve a new key for a stored address from the same board: assert the old entry is gone. Serve a stored key from a new address, or from another board: assert the old entry stays. |
| I-12 | Each family has its own key, replaced whenever that family's announced external address changes and at least every `KEY_ROTATE_H`, at a time independent of the other family's; a new address is never announced under a key seen with an old one; pair values use the current key of the entry's family only. | Change the reported IPv4 address; assert a new IPv4 key is announced, the IPv6 key is unchanged, and the old key never appears with the new address. |
| I-13 | An entry takes part only in rounds for blocks whose parent the tip reached after the entry was first received; the pair value depends on that block's hash and on both endpoints. | Insert an entry, connect one block: no attempt. Connect another: attempt. Change the block hash or either endpoint: different value. |
| I-14 | A board stores only elements whose endpoint it observed on the connection they arrived on, one per connection, for the connection's lifetime plus `BOARD_GRACE`; it holds at most `BOARD_VISITORS_MAX` visitors, `BOARD_PER_GROUP` per network group, and `BOARD_IP_CAP` entries per address; it sends entries only to its visitors, and its answer to a visitor's element contains the visitor's own entry exactly when it stored it. | Announce an endpoint other than the connection's: assert not stored and absent from the answer. Connect many times from one address and from one group: count. Disconnect: assert removal after `BOARD_GRACE`. |

### 11. Limits

| Name | Default | Used in |
|------|---------|---------|
| punch port | random in 49152 to 65535, fixed per run | Terminology |
| `WINDOW_MS` | 120000 | R-8.1 |
| `RETRY_MS` | 1000, doubled after each failure | R-8.2 |
| `GRACE_MS` | 5000 | R-8.7 |
| `HOLD_MS` / `HELD_MAX` | 10000 / 8 | R-8.4 |
| `PICKS_PER_ROUND` | 3, at most two per source group and one per network group | R-7.4 |
| `MAX_ACTIVE_SESSIONS` | 6 | R-7.4 |
| `TIP_LAG` | 2 blocks | R-7.1 |
| `GROUP_SESSIONS_PER_HOUR` | 4 | R-7.3 |
| `BOARDS` | 2 per announced family, in distinct network groups | R-5.2 |
| `BOARD_ROTATE_H` | 6 h | R-5.2 |
| `BOARD_FAIL_MAX` / `BOARD_BACKOFF` | 4 / 1 h | R-5.2 |
| `BOARD_VISITORS_MAX` / `BOARD_PER_GROUP` / `BOARD_IP_CAP` | 32 / 4 / 1 | R-5.5, R-5.7 |
| `BOARD_ACK` | 60 s | R-5.3 |
| `BOARD_GRACE` | 10 min | R-5.7 |
| `BOARD_REFRESH` | 30 min | R-5.8 |
| `PUNCHKEY_PER_HOUR` | 240 | R-5.10 |
| `SOURCE_CAP` | 64 | R-6.2 |
| `TABLE_MAX` | 1024 | R-6.3 |
| `ENTRY_TTL` | 1 h | R-6.4 |
| `KEY_ROTATE_H` | 24 h | R-4.3 |
| `HP_OUTBOUND_MAX` | 1 | R-9.1 |

## Rationale

[^numbers]: A survey among developers, posted in the discussion linked
in the preamble, found
endpoint-independent mapping in about two thirds of home IPv4
environments and no NAT at all on IPv6. Measurements of libp2p's DCUtR,
which does TCP simultaneous open with a relay as coordinator, report
about 70% success over millions of attempts.

[^why-not-relay]: Three reasons. Nothing in a relayed element can be
checked, so an attacker who injects invented
elements at a few dozen points lets honest relay carry them everywhere,
and every table ends up holding as much fiction as the attacker can
afford, about 240 live fakes per injecting connection. Two nodes only
pair if relay happened to deliver each to the other, which depends on
how far announcements spread and fails as the square of that. And the
one repair that keeps relay, forwarding only elements whose endpoint the
relayer saw connect, makes the relayers the announcer's long-lived peers
and tells everyone downstream who they are.

[^boards]: A board can check an announcement against the one thing an
announcer cannot fake, the connection it arrives on, so an honest board
holds only endpoints that really connected, and a lying board is just
one more peer bounded by the per-source rules. Two visitors of one board
hold each other by construction. And a board connection is purpose-made
and separate from the node's peers, so it reveals nothing about them.

[^standing]: A board can only tell a visitor what it holds while the
visitor is connected. With short visits, the earlier of two visitors
learns of the later one only on its next visit, so nodes would have to
revisit the same boards on a schedule and pairing would wait for the
revisit. A standing connection lets the board push each arrival to the
others at once, so two visitors hold each other within seconds, and it
doubles as a reporting peer that keeps the mapping alive. The cost is a
connection slot at the board, which is why boards keep visitors in a
small separate pool, and a visible relationship to the board, which the
rotation bounds. Nothing on that connection concerns the node's actual
peers.

[^service-bit]: Boards must be found among reachable nodes that are
deliberately not the visitor's existing peers, so the visitor has to
learn which addresses are boards before connecting. A service bit is
visible in address relay and the address manager, which makes that a
lookup instead of trial connections. The feature's `BOARD` flag confirms
it on the connection. The bit is experimental until the protocol is
assigned a number; implementations without the bit can fall back to
trying addresses and remembering which ones answered with `BOARD`.

[^punch-port]: Board connections are made from the punch port so that
the boards see the mapping others will punch to, report it, and keep it
alive for as long as they stay connected; nothing else has to use the
port. Binding every outbound connection to it instead would give more
reporters, but it would change the socket behaviour of connections this
protocol has no business touching, and it would show every peer a fixed
source port. The port is random rather than fixed because a
port-preserving NAT shows the local port to the world, so a fixed number
would mark the node's traffic to any observer, and because two nodes
behind one NAT would otherwise ask for the same port. Boards never need
to know it: they see only the mapped port, and the node learns that from
their reports.

[^backoff]: A node whose mapping differs per destination fails
verification at every board and would otherwise hop from board to board
for good, costing each a handshake. Two reporters in distinct groups
usually catch such a mapping before the first announcement, but not
always, so repeated failures are treated as the signal they are. Only an
acknowledgement clears the count, because with `BOARDS` of 2 per family a
count that also reset whenever a fresh pair of boards confirmed an
external address could never reach four, which is the case this is for.

[^unauthenticated-bit]: Service bits are advertisements nobody verifies,
so anyone who can get a few addresses into a node's address manager could
otherwise stop its hole punching an hour at a time by claiming the board
bit and then doing nothing. An advertised bit alone may never cost a node
more than one connection attempt. Counting only what a real board
produces also makes the pause mean what it says: that this node, not the
address, is the problem.

[^who-reports]: What makes a report meaningful is the local port, since
that is the mapping the punch attempts will use, so the rule is about the
connection and not about the kind of peer. It has to be a connection the
node opened, because a node whose punch port is also a listening port
would otherwise let anyone who dials in report an address for it, and two
such peers in different groups could invent an external address for it.
Waiting for the handshake costs nothing and drops a peer that opens a
connection and then says nothing.

[^rotation-secret]: The pair value works only because both sides compute
the same shared secret, and each computes it from its own secret key and
the other's public key. A node that kept the secret it computed before
its own rotation would keep pairing on a key its peers no longer hold,
and since a refresh recomputes nothing the mismatch would last as long as
the entry. Recomputing costs one multiplication per entry of the family.

[^min-version]: Taking the lower version lets an upgrade spread one node
at a time. Old nodes will read this field the way it is defined now, so
the rule cannot change later.

[^rotation]: Announcements reach every visitor of the node's boards and
tie a key to an address. Home addresses change, and a key that outlived
the change would let anyone follow the node from one address to the
next, which nothing else lets them do for an unreachable node. So a new
address never appears under an old key. Rotating more often than that
would hurt: every new key is a new entry in every table that waits a
block before it can be picked (R-7.2).

[^replace]: A board holds one entry per address, so when it sends a new
key for an address it has already replaced the old one. Mirroring that
at once saves the hour in which picks of the old key would otherwise go
unanswered, since the node computes with its new key only. The
replacement is accepted only from the board that supplied the old entry,
because a lying board must not be able to evict what another board
served. The other direction is never a replacement: a board verifies
addresses, not keys, so anyone holding an address can announce an
existing key from it, and letting a key carry an entry to a new address
would hand such a visitor the honest node's place in every table.

[^key-per-family]: Nothing else in the P2P protocol links a node's IPv4
and IPv6 addresses, and announcing both under one key would link them
for everyone who sees the announcements. So each family has its own key,
and the two rotate at independent times, since two keys that always
change together are linked by that alone. The cost is small: one more
key to hold, one more pair value per dual-stack peer, and the chance
that a pair is picked over both families in one round and ends up with
two connections, one per family. That is rare and costs a slot on each
side.

[^endpoints-in-hash]: Without the endpoints, every entry carrying a
given key has the same pair value whatever its endpoint says. A lying
board could serve a node's genuine key with invented endpoints, and
those entries would tie exactly with the genuine one; whichever sorted
first would be tried and the genuine one skipped. With both endpoints in
the hash, an invented endpoint gets a value unrelated to the genuine
entry's and competes like any other fiction, in proportion to how many
were planted. Grinding is unaffected: changing the endpoint makes a new
entry with a new `received_at`, exactly like changing the key.

[^coin-flip]: The initiator needs the single hole-punch outbound slot and
the responder an inbound slot. A fixed rule such as "the smaller key
initiates" would tie each pair to one combination for good, and a node
whose outbound slot is taken could never connect to half of its
candidates. Deriving the role from the pair value gives every pair a
fresh coin flip each round.

[^both-announce]: With no coordinator there is nobody to ask for an
introduction. A node that only wants outbound connections still has to
be on a board for others to find, so it announces too. A node with no
free slot of either kind has nothing to offer and nothing to gain, so it
leaves its boards and its entries lapse.

[^ip-cap]: A board can bound entries per address because it has seen
every entry's address connect; nobody can plant an entry for an address
they do not hold, so the cap cannot be used to starve anyone, and one
per address makes a spammer's many ports worth exactly one entry. Two
honest nodes behind one home NAT share an address, but each picks its
boards at random among all boards, so they rarely pick the same one; if
they do, the second is refused and picks another, which is bad luck
rather than a failure. A node whose mapped port changed arrives as a new
key on a new connection, since the key is tied to the address (R-4.3),
and replaces its own stale entry, which is in its grace period by then.

[^time]: Every address element carries a time, so the field has to hold
something, but nothing here depends on it: a board checks an entry
against its connection and keeps it while the connection lasts, and a
visitor expires entries by when it last received them. The board writes
the time it received the element so that the field says something true;
a receiver may show it and must not act on it.

[^ack]: The visitor cannot see whether the board stored its element,
and a board that saw a different endpoint, which happens when the
visitor's mapping is not the same towards every peer, would silently
hold nothing for it. Answering with the live list, the visitor's own
entry included, turns the list every visitor needs anyway into the
acknowledgement, with no extra message. The refresh repeats it, so a
visitor also notices if it has dropped off.

[^refresh]: Address messages have no way to withdraw an address, so a
visitor that leaves a board would linger in every table until it
expired. Re-sending every live entry on a schedule and expiring entries
that have not been re-sent gives a withdrawal for free: a departed
visitor fades from every table within `ENTRY_TTL`. The traffic is a few
kilobytes per visitor per refresh.

[^rate-limit]: A board sends each visitor at most one batch per refresh
plus arrivals, and a visitor sends its board one element plus changes.
The limit is a safety bound well above both, and counting rejected
elements means that a stream of invalid keys spends the sender's budget
rather than the receiver's processor.

[^source-cap]: What a board serves is the only way an entry gets into a
table, so a lying board is the only way fiction gets in. The per-source
cap bounds what one board can plant, and two picks per source group per
round bound what its entries can cost (R-7.4). Since every entry from
an honest board is real, admission needs no other defence; diversity of
the announced addresses is still checked at pick time (R-7.3), because
a lying board may invent them.

[^random-eviction]: For a full group, evicting at random means each
insertion evicts entries in proportion to how many the inserter already
holds, so a flood from a lying board mostly evicts itself, an honest
newcomer always gets in, and an honest entry survives each insertion
with probability 1 - 1/`SOURCE_CAP`. At the table ceiling, evicting from
the largest group hits exactly the group a lying board inflates.

[^last-seen]: Expiring from the local time of the last receipt trusts
nothing the announcer wrote and pairs with the board's refresh (R-5.8):
an entry lives while its board keeps re-sending it.

[^near-tip]: A round for `B` happens on each node when that node's tip
reaches `B`, so two nodes meet only if they reach it at about the same
time. A node that is catching up reaches `B` long after its peers did and
its windows never overlap theirs, so its attempts are wasted. It must
also stay out of every table while it is behind: a peer that picked its
entry would start a session and wait out the window alone, because the
node holds no round to punch back with. Initial block download is not a
sufficient test, since a node leaves it while still some way behind, and
the headers it already knows are what say how far.

[^reorg]: Nodes see a reorganisation to a chain of the same height at
different times or not at all, so a round on it would rarely find both
sides on the same block. Height advances in the same order everywhere.

[^block-trigger]: A new block is the one event every node sees within
seconds of every other, without any clock. Header timestamps are set by
miners and may be off by hours; rounds at fixed wall-clock times would
need clocks to agree, and a node with a wrong clock would punch alone
without noticing. The window absorbs the variance in when nodes connect
a block. A node catching up after being offline holds a round for each
block it connects, which nobody else is evaluating; the session cap
bounds that waste and the node is in step again at the next block.

[^parent]: The pair value is unpredictable only if the block did not
exist when the key was chosen. It is not enough to require the block to
arrive after the entry: whoever sees a block a second earlier than the
victim, which is ordinary propagation variance, can try keys against the
known hash for that second and still deliver the announcement first. A
commodity machine tries a few hundred thousand keys a second, enough to
land in the lowest three of a thousand. Requiring the entry to predate
the moment the tip reached the block's *parent* puts a whole block
interval between the last possible key choice and the first knowledge
of the hash; only a miner withholding two consecutive blocks could
grind, at a cost far beyond the prize. `received_at` is the node's own
clock, so it cannot be backdated. Tor's onion service directories use
the same ordering, a public random value fixed only after the keys it
is combined with, for the same reason.

[^same-nat]: Two nodes behind one NAT announce the same address with
different ports. Almost no home NAT lets a host reach its own external
address, so they would spend picks on each other every round. Excluding
any candidate at the node's own external address, whatever the port,
stops that.

[^services]: The initiator side of a session becomes an outbound
connection. An ordinary outbound peer is chosen for the services it
offers, and an entry's services are announced by the entry itself, so
the same requirement applies at pick time. The responder side accepts
whatever connects, as it does for any inbound connection.

[^one-ticket]: The pair value is the selection signal, so a lying board
that serves many entries holds many tickets, and the best of a hundred
draws beats the best of a few almost every round. That cannot be fixed
at the ranking, because the ranking is what makes both sides agree.
Taking at most two picks per source group per round caps what one
board's entries can cost at two picks in three, however many it served.
Two rather than one because a node's sources are its two boards per
family, and the honest case can only fill three picks if one source may
give two.

[^ranking]: Firing on a fixed threshold would make the number of
attempts grow with the table. Taking the lowest few gives a fixed number
of attempts per round, and the block hash makes a ranking as hard to aim
at as a threshold. The cost is disagreement: the value is the same on
both sides, but each ranks it against its own table. For tables of
similar size, a pair in one side's lowest three is in the other's lowest
three about 69% of the time, and in the lowest one 50% of the time. The
other attempts hold a socket for two minutes and connect to nothing.

[^window]: A pending `connect()` stays in `SYN_SENT` while the operating
system retransmits the SYN: about two minutes on Linux, with
retransmissions after 1, 2, 4, 8, 16, 32, and 64 seconds, and about 75
seconds on macOS. The first retransmission to arrive after the other
side's mapping exists completes the simultaneous open, so one pending
attempt covers the whole window with no retry schedule of its own, and
the two sides may start up to two minutes apart. R-8.2's retries matter
only when the far side answers with a reset, which a NAT without a
mapping does not.

[^hold]: Whichever node connects the block first sends first. Behind a
NAT the early SYN is dropped and retransmitted; a node with no filtering
at all accepts it before its own round has started. Holding the socket
untouched lets it become the session's connection when the round starts.
Held sockets are cheap and bounded, and a scanner gains nothing from
one, since nothing is ever sent on it.

[^extra-slot]: Using an ordinary outbound slot would let the
announcements a node happens to hold influence which ordinary peers it
has. One extra slot bounds the influence to one connection, and bounds
the network: with `HP_OUTBOUND_MAX` of 1, N participants hold at most N
punched connections. Since the slot is one and the role of a pair is a
coin flip, a round's picks hold at most one initiator and the rest are
responder side. The slot, not `PICKS_PER_ROUND`, is what limits how fast
a node gains connections.

**Why ECDH and not a hash of the two public keys?** A value anyone can
compute from two public keys and a block hash would tell anyone,
including the board, who connects to whom and when. The shared secret
needs one of the two private keys, so only the two nodes can compute the
pair value. Silent payments (BIP 352) use the same construction for the
same reason.

**Why is a board not a coordinator?** A coordinator chooses a pair and
tells both sides when to fire. A board holds what it has verified and
hands it to its visitors; it chooses nothing, times nothing, and cannot
compute a pair value, so it learns who visits it and nothing about who
connects to whom. A lying board is bounded like any other peer. What it
shares with a coordinator is that it is a reachable node doing work for
unreachable ones, which is said here so that nobody has to discover it.

**Why no signature on announcements?** A board verifies the endpoint
against the connection, which no signature could do better, and a lying
board could sign whatever it likes. The only thing a signature would add
is an unforgeable `time`, which nothing depends on.

**Why a dedicated punch port and not the P2P port?** Reusing the
listening port would need `SO_REUSEPORT` on the existing listener, a way
to tell punched connections from ordinary inbounds on one socket, and
would leave out nodes that do not listen at all. On a dedicated port
every accepted connection is a punched one, and `-listen=0` still works.

**Why nothing is retried or reported.** A failed session says nothing
the node could act on: the other side may have had no free slot, may
have rejected the network group, or may have ranked the pair lower
against a larger table. All of that resolves itself with the next board
refresh and the next block. Retrying would only send more SYNs to the
same address.

**Not taken.** Ordinary address relay for announcements, and relay of
verified announcements one hop onward (see [^why-not-relay]); short board visits
with a revisit schedule, and replication of entries between boards,
which would be relay again (see [^standing]); a threshold instead of a
ranking; proof of work on keys (it prices fiction at a few dozen cores
and does nothing a board does not do better); attestation of addresses
by relaying peers; keeping announcements in the address manager; binding every outbound
connection to the punch port (see [^punch-port]); a proof of the
announcement key on the punched connection, which with verified
endpoints would mostly reject real connections that a lying board had
mislabelled; keeping old keys usable after rotation; one key for both address families
(see [^key-per-family]); a table keyed by the announced address.

## Backward compatibility

Nodes that do not implement this document are unaffected: the `feature`
message is ignored per BIP 434, an unknown service bit is ignored,
`PUNCHKEY` elements carry an unknown network ID and are skipped by
BIP 155 receivers, and they are only ever sent on board connections,
which only exist between nodes that both signalled support. Nodes
announcing a protocol version below 70017 are not sent the feature.
Ordinary connections are untouched; only boards and punched peers ever
see the punch port.

## Security considerations

Anyone can claim any endpoint and any key. The design accepts a claim
only from a node that proves it holds the endpoint by connecting from
it, and bounds everything else by the connection it arrived on, which
is the one thing an attacker cannot fake.

**Invented addresses.** An honest board stores only endpoints it saw
connect, so fiction cannot pass through it. To fill a board an attacker
needs real addresses: one entry per address, four visitors per
network group, and the pool is full at thirty-two, after which honest
visitors go elsewhere. Those entries are real hosts, so when picked they
complete a connection and are sybil peers rather than wasted SYNs, and
the per-group session cap and inbound treatment apply to them.

**Lying boards.** A board can serve whatever it likes to its visitors:
invented endpoints, replayed keys, a sybil roster, or nothing. Each
visitor bounds a board like any other source: at most `SOURCE_CAP`
entries, two picks per round (R-7.4), and the announced network group
must pass diversity. Two boards per family in distinct groups mean one
lying board cannot blind a node, and rotation limits how long one is
trusted. A board that invents endpoints makes its visitors send bounded
SYNs at third parties, as reflection below. Because the pair value
includes both endpoints, a replayed key under invented endpoints does
not collide with the genuine entry (R-4.5). Running many boards buys an
attacker no more than running many peers: a visitor's picks from one
board are capped, and its hole-punch outbound still has to pass
diversity and complete a handshake from a real host.

**Flooding a visitor.** A visitor processes at most `PUNCHKEY_PER_HOUR`
elements per board, holds at most `SOURCE_CAP` per board, and random
eviction means a board that floods its own share mostly evicts its own
entries. Nothing a board sends can displace entries from another board.

**Reflection.** The only traffic sent to an unverified address is a
session's attempts: one pending `connect()`, whose SYN the operating
system sends about seven times in two minutes, re-opened at most seven
times and only if the far side answers with resets. Only a lying board
can point a node at a third party, each such entry is attempted once and
dropped, every node starts at most `GROUP_SESSIONS_PER_HOUR` sessions
per hour into one network group, and endpoints must be routable and not
reserved, local, the node's own, or on a bad port.

**Starving a node.** Nobody but the node itself can create or replace an
entry for its address at an honest board, since doing so requires
connecting from that address. A lying board can omit the node; its other
board still serves it. A node's entry in a visitor's table is replaced only by the board that
served it, for the same address with a new key (R-6.1), so a lying board
can churn its own entries and nothing else; a key seen from a new
address never displaces the entry the node announced itself.

**Grinding.** The key must be in the victim's table before the victim's
tip reached the parent of the block whose hash enters the pair value,
and `received_at` is the victim's clock. A board can choose when to pass
an entry on, but not what block comes next. Only a miner withholding two
consecutive blocks could grind (see [^parent]).

**Sybil and eclipse.** The hole-punch outbound is one extra slot, kept
out of anchors and diversity accounting, and its peer must pass outbound
diversity. Taking it needs a real host in a network group the node
lacks, a ranking the attacker cannot influence, and at most two picks
per round per board the attacker controls. On the responder side, unreachable
nodes become reachable to anyone with a real host on the same board;
those are inbound connections with inbound treatment, and the per-group
caps bound how many one attacker can hold. Boards are chosen from the
address manager, so poisoning it gets an attacker's boards chosen in
proportion to its share, as in any eclipse attempt; the address manager's
own defences bound that, and two boards per family in distinct groups
mean both must be the attacker's.

**Board exhaustion.** A board's visitor pool is separate from its inbound
limit, small, and capped per network group and per address, so filling
it costs real addresses in several groups and denies only that board.
A board may also simply refuse visitors.

**Chain dependence.** A node starved of blocks holds no rounds. Delaying
its blocks delays its rounds but cannot choose the pair values without
mining. A node catching up holds rounds nobody else evaluates, bounded
by the session cap. A wrong clock changes nothing, since no clock enters
the protocol.

**Resources.** At most `TABLE_MAX` entries of under a hundred bytes; at
most `MAX_ACTIVE_SESSIONS` pending attempts and `HELD_MAX` held sockets,
which are never read or written and are closed after `HOLD_MS`; at most
`BOARD_VISITORS_MAX` board connections at a board; one hash per eligible
entry per round.

**Reports.** A board can report any address. Only two reporting peers
in different network groups make an external address, and a single
dissenter changes nothing (R-2.2); a node's boards are in distinct
groups for that reason. Two lying boards that agree on a false address
only make the node announce something honest boards will not verify.

**Privacy.** No announcement names a peer, no board can compute a pair
value, and nobody but the two nodes learns which pairs connect. A board
learns its visitors' endpoints and keys, which are what they announce,
and for how long they stay; visitors learn who else is on the same
board. None of that touches the node's actual peers, which stay as
hidden as before. What is public is participation: a home node's
clearnet endpoint, under a key that identifies it for up to a day and is
tied to one address (R-4.3), which is why taking part is opt-in. A
node's IPv4 and IPv6 endpoints carry different keys, so the protocol
does not link them (R-4.2). Ordinary peers see nothing of this protocol;
only boards, punched peers, and on-path observers see the punch port,
and SYNs from it shortly after each block mark the attempts to anyone on
the path.

## Reference implementation

A reference implementation for Bitcoin Core is planned and will be
linked here. Test vectors are in
[`bip-tcp-holepunch-coordinatorless/`](bip-tcp-holepunch-coordinatorless/):
[`vectors.json`](bip-tcp-holepunch-coordinatorless/vectors.json),
generated by
[`gen_vectors.py`](bip-tcp-holepunch-coordinatorless/gen_vectors.py).

## Test vectors

`vectors.json` holds valid and invalid encodings of the `feature` payload
and of `PUNCHKEY` elements for both families, each with decoded fields
or the expected rejection reason, and pairing vectors: for three fixed
keys with fixed endpoints and two block hashes, the public keys, the
shared secret, the block hash in both byte orders, the sorted endpoints,
the pair value, the role bit, and the initiator, plus the ranking a node
holding two of the entries derives. Implementations are expected to
reproduce every encoding byte for byte, reject every invalid vector, and
reproduce every pair value and role. The vectors use documentation
address ranges, which are not globally routable, so an implementation
checking them against its own validator has to waive routability as it
does on a test network (R-2.5); routability and the other checks in
R-2.1, R-5.1, and R-7.3 still apply to real elements.

## Changelog

* 0.4.9 (2026-10-18): a node holds rounds and announces only while its
  blocks are within `TIP_LAG` of the best header it knows. Leaving
  initial block download is not enough: a node that is catching up
  reaches each block long after its peers, so its windows never overlap
  theirs, and its own entry in their tables only costs them a session.
* 0.4.8 (2026-10-18): a report counts on any connection the node opened
  from a punch socket, and only once the handshake on it is complete, so
  the rule names the connection and not the kind of peer; replacing a
  family's key recomputes the shared secret of every entry of that
  family, which the pair value needs in order to stay agreed; only a
  disagreeing report and a missing acknowledgement count towards the
  board pause, since the board service bit is an unauthenticated
  advertisement, and only an acknowledgement clears the count; an
  element's length must match its `net`; a `PUNCHKEY` element on any
  other connection disconnects; board candidates must advertise
  `NODE_P2P_V2`; the test-network group waiver covers source groups and
  the per-group session budget; the 4-tuple error is named.
* 0.4.7 (2026-10-18): a board connection is restricted from `verack`
  on, the handshake before it is the ordinary one; up to two picks per
  source group per round, so that two boards can fill three picks; an
  initiator pick needs the services required of an ordinary outbound;
  `BOARD_ACK` bounds the wait for the board's answer; a board may count
  a visitor as inbound until its feature arrives; test-network waivers
  compare endpoints where all nodes share an address.
* 0.4.6 (2026-10-18): an element from a board for an address it already
  served, with a new key, replaces the old entry at once; a key seen
  from a new address never replaces anything.
* 0.4.5 (2026-10-17): ordinary outbound connections no longer use the
  punch port; boards and punched peers are the reporters; a visitor
  avoids boards it is otherwise connected to, replaces a board whose
  report disagrees, and backs off after repeated failures; the
  connection proof recorded as not taken.
* 0.4.4 (2026-10-17): `time` carries no meaning and its window check is
  gone; a board answers an element with its live entries including the
  visitor's own, which acknowledges the registration; entries in their
  grace period are no longer served; note on board choice and the
  address manager.
* 0.4.3 (2026-10-17): the rationale is made self-contained and the
  reference to another draft removed.
* 0.4.2 (2026-10-17): one entry and one connection per address at a
  board; boards chosen uniformly at random; a refused visitor moves to
  another board, so two honest nodes behind one NAT rarely share one.
* 0.4.1 (2026-10-17): the reasons against address relay get their own
  footnote, cited from the motivation.
* 0.4.0 (2026-10-17): boards replace address relay: announcements go
  over standing, limited-purpose connections to reachable nodes that
  verify each endpoint against the connection and push entries to their
  visitors; service bit and feature flags for finding and marking
  boards; per-address and per-group caps at boards; both endpoints in
  the pair value, which removes the tie a replayed key produced; the
  one-session-per-key rule dropped; candidates at the node's own
  external address excluded; batch time for reorganisations.
* 0.3.1 (2026-10-17): one key per address family instead of one per
  node, rotated independently, so that a node's IPv4 and IPv6 endpoints
  are not linked by the protocol.
* 0.3.0 (2026-10-16): full rewrite.
