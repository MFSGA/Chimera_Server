# Vendored `watfaq-netstack`

This source snapshot comes from `MFSGA/Chimera_Client/clash-netstack`, package
version `0.26.3`. The upstream base is commit
`6e951d59976c22a65238e8a70069971a6dfea4ae`; the vendored source includes the
two subsequent Client commits `925d4b1b66a543956c61239776196cd9d17e5c5d` and
`8fc9b2b3821a571f806cda6cc4df68bef8ad1b46`.

Those changes add an explicit, awaitable TCP listener shutdown path and redact
packet payloads from malformed-packet diagnostics. The latter is required for
the Server's no-secret-in-logs rule. The Client commits are local and not yet in
the public Git history, so the Server carries this reviewable source snapshot
instead of depending on an unpublished revision or another checkout's path.

The Server also carries a local change in `src/udp_socket.rs`: `SplitWrite`
fragments oversized IPv4 and IPv6 UDP IP packets to the configured MTU (1500
by default). `NetStack::new_with_mtu` applies that same value to smoltcp's
device capabilities and UDP fragmentation. It reserves queue capacity for the complete fragment set before sending
any fragment, so bounded-queue pressure drops a whole UDP datagram instead of
publishing a partial one. A routed Office-LAN-host namespace test exposed this
gap: returning a 4 KiB UDP response as one oversized IP packet failed across a
1500-byte veth. The Server-only fragmentation tests cover reverse-order
reassembly for both address families, configured 1280-byte IPv4/IPv6 output,
and atomic drop when the packet queue cannot fit the whole datagram. The
reassembler also has a 30-second state TTL;
UDP readers and the TCP/ICMP packet loop scan once per second only while
fragment state exists, so incomplete sets are released during quiet periods
without waking ordinary empty readers. Tokio paused-time unit tests cover both
consumer paths. This is a Server-only lifecycle delta from the Client snapshot.

A further Server-only Xray TUN compatibility constructor additionally implements
the four RFC 8200 action classes for unknown IPv6 Destination Options after
Fragment reassembly. The Xray-only path skips unknown action-00 options,
discards action-01 options, and sends a bounded ICMPv6 Parameter Problem
(type 4/code 2) for action-10/11 unicast options, preserving the reassembled
packet in the quote and pointing at the offending option. The ordinary
constructors remain strict; the TCP/ICMP packet loop uses nonblocking output
for generated errors. Vendor tests and a live pinned Xray 26.9.9 comparison
verify option types `0x1e`, `0x5e`, `0x9e`, and `0xde`. The opt-in
Xray path also rejects IPv6 fragment-zero Destination Options chains that
lack a complete subsequent ICMPv6 header, avoiding a spurious Parameter
Problem when an overdeclared `Hdr Ext Len` overlaps valid ICMP bytes. A
pinned-Xray Linux namespace comparison tests three malformed header layouts
and a complete positive action-10 header chain. A further regression probes
two consecutive Destination Options headers: with 16 fragment-zero bytes the
incomplete ICMPv6 header chain is rejected in opt-in Xray mode, while a 24-byte
first fragment permits Echo and still generates Parameter Problem code 2 /
pointer 50 for an action-10 unknown option in the second header. A separate
Xray-only UDP reassembler guard now checks that the first fragment contains
an entire UDP header after one or two padding-only Destination Options headers,
matching the pinned live Xray 26.9.9 behavior without enabling unknown-option
ICMP errors on the UDP path. For TCP after one or two padding-only Destination
Options headers, pinned Xray drops a fragment-zero packet containing zero TCP
bytes but accepts eight TCP bytes, even when the remaining 24-byte TCP SYN/MSS
header is in the following fragment. An opt-in first-fragment guard matches
this narrow TCP boundary without claiming full TCP/RFC 7112 conformance.
The live pinned Xray 26.9.9 matrix additionally confirms this same eight-byte
minimum with valid TCP SYN headers of 20 bytes (no options), 24 bytes (MSS),
and 40 bytes (MSS and NOP padding) across one/two Destination Options headers
and first-fragment splits inside the TCP options. A new vendored regression
pins these cases without further runtime changes. Pinned Xray/gVisor also
accepts checksum-valid fragmented IPv6 SYNs whose MSS/Window Scale or unknown
TCP option length is invalid, stopping option parsing rather than rejecting
the SYN. The opt-in Xray TUN TCP packet pump now retains any valid prefix and
replaces the malformed TCP option suffix with inert NOPs after verifying the
*original* TCP checksum; ordinary site-gateway parsing stays strict. A live
out-of-order fragmented IPv6 test additionally shows Xray sends bare RST for
unmatched ACK or FIN+ACK even when the TCP options are malformed, while
inbound RST remains silent. The opt-in normalization now also accepts only
pure ACK/FIN+ACK flags for this case; default handling stays unchanged. A live
Xray namespace comparison and vendor regression cover one/two Destination
Options headers, two first-fragment TCP splits, and bad-checksum rejection.
A follow-up pinned-Xray Data Offset probe shows that both TUNs reject
fragmented IPv6 SYNs with TCP Data Offset 0/4 or overdeclared 15, but accept
valid 5/6 with four NOP bytes; a new vendor regression covers the boundaries
with both default and opt-in modes. No runtime changes were necessary for
Data Offset, and the malformed option-length fallback remains Xray-only.
An established-flow IPv6 TCP test now confirms that Xray TUN permits
checksum-valid fragmented ACK data and FIN+ACK tail data with malformed MSS
or unknown option lengths, matching pinned Xray 26.9.9's echo behavior;
original-checksum rejection, same-fragment-ID recovery, and default strict
parsing are covered by the new integration regression. The Linux namespace
comparison uses temporary nftables protection for raw TCP handshakes, with
cleanup, and records inbound-FIN acknowledgment and outbound peer FIN as
separate checks. A two-second observation boundary initially missed Xray FINs:
observed FINs arrive about 2000–2002 ms after inbound FIN, not immediately
as on Chimera. The live probe now allows four seconds and checks that both
FIN acknowledgment and peer FIN occur without requiring identical timing.
The vendor integration regression also confirms that writing to the send half
after reading FIN/EOF still emits TCP data. A new live active-connection RST
probe verifies that pinned Xray also releases and reopens the same TCP tuple
after a checksum-valid fragmented RST+ACK with a malformed MSS or unknown
option length, unlike Chimera's old strict option decoder. The Xray-only
compatibility normalizer now includes precisely RST+ACK in its flags
allowlist; a vendor test pins same-tuple recovery and no duplicate
application data was seen in the live retransmission probes. A follow-up
pinned-Xray live comparison establishes that **bare RST** with malformed
TCP option lengths also releases an established IPv6 fragmented TCP flow;
the opt-in normalizer now includes exact flags `0x04` (bare RST). The live
probe first injects an out-of-window RST+ACK, confirms it does not kill the
connection and checks additional echoed data, then proves same-tuple SYN
recovery after both exact-window RST+ACK and bare RST. The vendored regression
covers both flag layouts, the far-window guard and default strict mode.
Original checksum validation and unfragmented/default-mode behavior remain
unchanged. A near-window follow-up measured that gVisor ignores a fragmented
RST with sequence RCV.NXT-1 **despite nonempty trailing TCP payload** and
continues echoing data, whereas smoltcp counted the payload toward window
overlap and prematurely aborted that active connection. For opt-in Xray TUN
only, the normalized reassembled IPv6 RST/RST+ACK has trailing data removed
*after original checksum verification*; the TCP and IPv6 lengths and new
checksum are updated consistently. This applies even to valid NOP options
and preserves a subsequent RST at RCV.NXT+1 as an effective reset. The
vendor regression exercises the -1 keepalive/survival boundary with live
application data after injection. A remaining pure-ACK difference is measured:
smoltcp sends a challenge ACK for RCV.NXT-1, while pinned gVisor did not in
these probes; no risky global Challenge ACK suppression is applied.
A repeat-timing check on one/two Destination Options control flows shows
smoltcp/Chimera emits an ACK for the first RCV.NXT-1 RST, no ACK for an
immediate duplicate, and an ACK again about 1.12 seconds later for a
**header-only** fragmented RST. Pinned Xray 26.9.9 emits no ACK at any of
those points; both remain connected and can echo data. The strict original
checksum barrier is now reinforced in the vendored RST integration test by
corrupting a valid in-window bare RST / RST+ACK (with normal and malformed
options) before reassembly/normalization, then proving application data
still reaches the active stream. No runtime behavior was changed in this
follow-up. This is not a blanket RST or Challenge ACK compatibility claim,
nor full IPv6 option semantics or general fragmentation parity.

A separate fixed-Xray 26.9.9 active-TCP **pure ACK** window test checks
out-of-order fragmented IPv6 ACKs in one/two Destination Options layouts
using independent established streams and verified before/after echo.
Unlike unacceptable RST, an ordinary ACK with sequence RCV.NXT-1 or a
far-out-of-window sequence **does** receive a pure ACK from both smoltcp
and gVisor; RCV.NXT+1 receives no reply from either. A future ACK number
beyond any TCP data sent by the server receives an ACK from smoltcp but
**no reply** from the pinned gVisor reference, with both streams still
usable. The live probe asserts this reply matrix per implementation, not
false parity. New vendor regression
`active_ipv6_tcp_future_ack_challenges_but_preserves_stream_data` pins
smoltcp's local reply and subsequent payload delivery in the default and
Xray-only stacks. No production TCP response suppression was introduced.

A later dedicated established TCP **zero receive window** probe pins
real network-namespace behavior on both Chimera and Xray 26.9.9. Raw IPv6
client traffic first advertises window zero, then sends a fragmented ACK
carrying application data through one or two padding-only Destination
Options headers. Both implementations ACK the inbound data and withhold
the complete TCP Echo payload while the advertised receive window is
closed. Chimera/smoltcp emits a 1-byte probe at the first post-SYN
server data sequence (offset zero); pinned Xray/gVisor emits 1-byte
probes at the previous already-acknowledged sequence (offset -1).
After a fragmented nonzero-window update, the client reassembles and
acknowledges the full Echo, and subsequent new data echoes normally.
The live probe enforces probe length and per-implementation sequence
conventions but not equal retry counts/timers. New vendor regression
`active_ipv6_tcp_zero_window_defers_outbound_until_window_update`
checks buffering, withheld payload and post-reopen stream delivery
for both default and Xray-opt-in stacks. The follow-up live loss fixture
deliberately drops the **second IPv6 fragment of the first nonzero-window
update**, checks that the TCP receive window stays closed and one-byte
probes continue, then resends the complete window update with a fresh
fragment ID. It also deliberately withholds the ACK for the first complete
Echo response, confirms a duplicate TCP segment with the **same sequence
and bytes**, acknowledges that retransmission without duplicating buffered
application data, and checks subsequent new Echo data. Both Chimera and
pinned Xray passed **2/2** live extension-chain cases. The same vendor
regression now tests the incomplete first update (its final fragment is
absent, Fragment ID `0x55667721`) followed by a *complete* out-of-order reassembly at new ID
`0x55667722`, for both default and opt-in stacks. No production sender
change was needed. An extended persist control now keeps the **two-
Destination-Options** case at receive window zero for roughly 14 seconds,
recording monotonic probe timestamps instead of assuming short-window
timing applies indefinitely. In the direct comparison, Chimera's
one-byte probes are spaced by about **2 then 4 seconds**, while
pinned Xray's one-byte probes show about **0.4, 0.8, 1.6,
3.2 and 6.4-second** gaps. The test also verifies a complete window
retransmission still restores the Echo and allows fresh data on the same
connection; the longer zero-window interval can postpone *subsequent*
TCP data retransmission, so the long case observes retransmitted data
over a longer separate horizon rather than calling an arbitrary short
timeout a failure. In the long-stall live case, Chimera retransmitted
the first Echo roughly **1 second** after reopening; pinned Xray did
so after roughly **12.8 seconds** (outside the old 4.5-second window).
Both streams remained usable and echoed a second message correctly.
The local vendor regression now keeps the incomplete
window update pending for 3.4 seconds in **both** default and opt-in
modes, requires a one-byte probe and answers probes without opening the
window before the complete new-ID update. No TCP sender change was
needed. A scaled-window follow-up adds a third independent live TCP
connection: the client's SYN offers **Window Scale 3** (valid RFC option),
and both Chimera and pinned Xray reply with a Window Scale SYN-ACK
(Chimera shift **3**, Xray shift **8** for their own receive direction).
After a zero window and the same lost-fragment/window-update protocol,
a *new* fully reassembled ACK advertising raw window field **1** must
release **no more than eight bytes** on the server→client TCP stream
because the client offered WS=3. Both oracles send exactly eight bytes,
then deliver the remainder only after the large-window update, recover
from the intentionally dropped data ACK and echo a fresh message.
The existing vendor integration test now covers both default and opt-in
stacks **with and without** WS=3, checking actual SYN-ACK negotiation,
the eight-byte limited window, the incomplete-first-update barrier and
full stream recovery. This does not establish all possible WS shift
values, receive-side scaling throughput, SACK or multi-minute timers.

A focused valid-SYN option matrix adds live WS=0 and WS=1 controls,
keeping the original unscaled and WS=3 TUN connections. Their effective
server→client windows at raw advertised field one must be exactly
**1, 2 and 8 bytes** respectively before acknowledging further data.
The WS=1 live control fragments an otherwise valid **40-byte TCP SYN**
out of order after IPv6 Destination Options, with eight TCP header
bytes in fragment zero and valid MSS=1280, SACK-Permitted, WS=1 and
Timestamp options. Both Chimera and pinned Xray negotiate MSS/SACK/WS
and correctly honor the narrow two-byte send window. They differ on
optional Timestamp negotiation: Chimera/smoltcp **omits TS in SYN-ACK**
(default socket has no timestamp generator); pinned Xray/gVisor
**includes TS**. The client only sends TCP Timestamp on later ACK/data
packets if the SYN-ACK negotiated it, so both preserve Echo and window
recovery. Data retransmission after the deliberately lost first ACK
is observed with an extended horizon in the Timestamp case: the pinned
Xray compound-WS=1 flow retransmitted after about **6.14 seconds**, versus
about **1 second** in Chimera, without losing or duplicating app bytes.
All **5/5** independent zero-window control flows passed against each
TUN implementation, including short/long persist, WS=0/1/3, window
update fragment loss and fresh-data continuation. A short deadline is
not a reliable failure signal. The vendor integration
regression `fragmented_ipv6_tcp_compound_syn_options_keep_stream_usable`
further tests **eight** default/opt-in combinations with fragmented
compound SYNs offering WS shifts **0, 1, 7, 14**, verifying valid
SYN-ACK options and real application-byte delivery with timestamp
fallback as negotiated. This does not prove full SACK recovery,
timestamp PAWS/replay or throughput at large scaled windows.

A dedicated **receiver SACK / missing TCP segment** fixture now supplies
a valid MSS=1200 SYN with SACK Permitted **on or off**, independently
for one or two IPv6 Destination Options headers after Fragment.
The first application segment is withheld, while a later data segment
arrives in two reverse-order IPv6 fragments (only eight TCP bytes in
fragment zero). The server must keep its cumulative ACK at RCV.NXT
and advertise the exact SACK block covering the out-of-order tail
**if and only if** SACK was negotiated; it must not deliver the tail
prematurely. Both Chimera and pinned Xray pass **4/4** live cases:
the missing TCP prefix completes the byte stream, the original Echo
is recovered exactly once, and further fresh data succeeds on the same
TCP connection. A new vendored regression
`fragmented_ipv6_tcp_sack_gap_reassembles_once_and_is_negotiated`
asserts SACK/no-SACK SYN-ACK semantics, the exact selective block,
no application data before the gap fills, correct reconstruction,
no redelivery of a later duplicated tail segment, and fresh data
continuity in **both** ordinary/default and Xray-opt-in constructors.
This validates **receiver SACK**, not the outbound sender's response
to SACK scoreboard reports, multi-hole recovery or DSACK.

The follow-up `established_ipv6_tcp_sender_handles_sack_gap_and_cumulative_recovery`
regression now tests **sender-side SACK feedback and duplicate-ACK
recovery** in four combinations: ordinary/default or Xray-opt-in
constructor, each with or without SACK negotiation. The synthetic
client ACKs only the first actual outgoing segment of a deterministic
2100-byte TCP write (MSS=536), pretends the next segment was lost and
reports a *later, actually received* TCP segment as SACKed, using a
valid TCP SACK option and four duplicate cumulative ACKs. It requires
byte-identical retransmission of the unacknowledged gap; only received,
contiguous data is cumulatively ACKed thereafter. All bytes and a
second fresh write must arrive correctly. The real Linux namespace
fixture repeats the two SACK on/off cases against both Chimera and
pinned Xray 26.9.9, with **2/2** successful retransmission/recovery
flows per implementation in its initial direct comparison. Chimera
emitted initial segments at offsets 0/536/1072; the pinned Xray with
SACK emitted 0/500/1000. Packet segmentation and retry timing are
not required to match. gVisor has a sender SACK scoreboard while
smoltcp's established ACK processing primarily uses cumulative ACK,
three duplicate ACKs and the retransmission timer; recovery of this
**single emulated missing outgoing segment** does not establish the
same optimized selective sender recovery, two-hole loss or DSACK.

The double-gap sender fixture extends this with a **3500-byte**
Echo, five actual outgoing segments and two emulated lost,
nonadjacent segments. With SACK negotiation, its four duplicate
ACKs carry **two disjoint SACK blocks** (TCP kind 5/length 18,
20 padded option bytes), each covering only valid server bytes
actually observed by the synthetic client. After the first
hole's exact retransmission it sends a deliberately **partial
cumulative ACK** stopping at the second hole, reports its
remaining SACK block and requires the second gap's correct
retransmission. No-SACK controls send no SACK blocks. Both
Chimera and pinned Xray passed **4/4** live sender cases:
two original single-gap and two double-gap. They recover every
original Echo byte, retransmit both gaps and preserve a
second fresh application write. The vendored regression
`established_ipv6_tcp_sender_two_sack_holes_recover_after_partial_ack`
covers **four** default/Xray constructor × SACK enabled/disabled
combinations and checks the identical partial-ACK, gap-repair,
data integrity and stream-continuity invariants. Chimera's
outbound segment offsets begin 0/536/1072/1608/2144;
pinned Xray's SACK-enabled response begins
0/500/1000/1500/2000. Emulated loss recovery does not
imply equivalent gVisor SACK scoreboard, loss timing,
congestion control or sender DSACK support.

The next SACK sender regression adds **reneging and genuine DSACK**
across the default and Xray-opt-in stack constructors. The raw client
first sends a valid selective-ACK block only for data it has actually
received, then **discards that previously SACKed range** and stops
reporting it. Its cumulative ACK may advance only across bytes that
have been received again. Both Chimera and pinned Xray recover the
former SACKed range, finish the original 2100-byte Echo, and continue
transmitting new data; they do not permanently treat the old SACK as
a guarantee that the peer still holds those bytes.

A separate DSACK control withholds the ACK for a small real Echo
until the raw client actually sees **two copies** of the same
TCP sequence and payload. It then cumulatively ACKs that range
and attaches a TCP SACK block **below** the ACK number, the
RFC 2883 duplicate-SACK pattern, and requires a fresh application
Echo on the still-established stream. The fixed Xray comparison
observed duplicate payloads at about 0.2 seconds; Chimera at about
1.0 second. The local regression
`established_ipv6_tcp_sack_reneging_and_dsack_preserve_stream`
tests **both** default and Xray-opt-in stacks, including actual
bytes, correct cumulative ACK advancement, genuine duplicate
evidence, and a subsequent write. These are loss-emulation and
retransmit-timer safety checks, **not** full SACK reneging under
memory pressure or DSACK-based spurious congestion-recovery parity.

A focused TCP Timestamp/old-sequence replay matrix uses a SYN offering
`TSval=40000`, then validates the *actual* SYN-ACK option negotiation
with Chimera and fixed Xray 26.9.9. The pinned Xray/gVisor **does**
negotiate Timestamp, whereas the vendored smoltcp 0.13.1 sockets
do **not** (the Timestamp generator is disabled for both default and
opt-in constructors). In the fixed-Xray real Linux TUN oracle, after
receiving valid `TSval=41000` data, **new-sequence TCP data using a
stale `TSval=40001` was still accepted and echoed** across both
one-/two-Destination-Options IPv6 fragment layouts, with only eight
TCP header bytes in fragment zero. This is a recorded PAWS limitation
of the pinned external behavior, not a reason to claim strict
timestamp-age rejection. The Chimera control must send **no TS option**
after SYN-ACK declines it; its plain new-sequence data also succeeds
but it is not a PAWS test. Both implementations suppress a replay
of previously accepted **old TCP sequence bytes**, under a new IPv6
fragment identifier, then echo fresh TCP data on the same connection.

The new vendor regression
`established_ipv6_tcp_timestamp_decline_replay_and_recovery`
now covers **eight** combinations: default/Xray-opt-in constructors
× one/two IPv6 Destination Options headers × SYN TSval 40000 or
`0xfffffff0` close to the 32-bit wrap boundary. It explicitly pins
the unnegotiated Timestamp SYN-ACK and tests old-sequence duplicate
suppression, once-only application delivery and same-flow recovery.
Each case also deliberately injects an anomalous established TCP
segment **with a Timestamp option despite its SYN-ACK declining TS**,
then checks exact application bytes. If the peer rejects the unsolicited
option, the test retransmits the same sequence as a standards-compliant
plain TCP packet and verifies recovery; finally another plain data
segment must still pass. This verifies robust parsing/fallback, **not**
PAWS on smoltcp, since no generator/negotiation exists in this mode.

The corresponding live oracle now tests both baseline TS values and
two additional TCP sessions where the client TSval advances across
`0xfffffff8 -> 0x00000008`, and separately sends data without TS
on an Xray session which did negotiate it. Xray TSecr values on
actual echoed data and missing-option accept/drop behavior are
recorded rather than assumed to conform to identical TCP options
on smoltcp. No TCP runtime code changes were needed. Timestamp
option negotiation, PAWS enforcement, timestamp expiry/wraparound
and TIME_WAIT handling are separate properties and are not claimed
generally equivalent.

The new TCP **active-close / TIME_WAIT direction** oracle adds a
dedicated real Echo target marker that echoes bytes and then closes
its TCP socket **first**. In two raw IPv6 fragment-chain layouts,
the Chimera TUN side forwards a server-first FIN, acknowledges the
client's later FIN and then accepts a fresh higher-ISN SYN on the
*exact same four-tuple*, delivering the next Echo correctly. The
pinned Xray 26.9.9 forwards the full first Echo but **does not emit
the server-first FIN within the same bounded observation window**.
The client then initiates its FIN, receives a completing FIN/ACK
exchange, and can also reopen the same four-tuple for a fresh Echo.
These are **different close-state paths**: Chimera's sequence
demonstrates server-side FIN-WAIT/TIME-WAIT direction; Xray's
fallback demonstrates client-first shutdown and cannot be claimed
as a real gVisor TIME_WAIT probe. Neither implementation emits
old application bytes after replay of the previous connection's FIN.
The new `active_ipv6_tcp_fin_timewait_duplicate_fin_and_same_tuple_reopen`
vendor regression passes both default and Xray-TUN-compatible
constructors in one/two IPv6 Destination Options layouts, asserting
the real server-first FIN, its final ACK, a duplicate IPv6-fragmented
FIN under a fresh fragment identifier, and successful new stream data
after a higher-ISN SYN on exactly the original address/port tuple.
The test also replays a genuinely delivered old client
application segment at its original sequence under another
fresh IPv6 fragment ID before the tuple is reused; the new
stream must see only its own new data. The live fixture
likewise replays the old Echo request bytes after FIN and
**asserts** that both implementations accept the higher-ISN
same-four-tuple SYN and return the fresh, exact Echo, rather
than treating a diagnostic SYN-ACK as a success. The local
test does **not** enable Timestamp, so it doesn't verify
Xray TIME_WAIT PAWS, FIN-timer reset, assassination or
long-term reuse behavior.

The next `14.15` investigation adds a second target-side EOF
trigger to the live Linux namespace fixture. In addition to a
fully closed Echo target socket, a separate marker explicitly
calls `shutdown(SHUT_WR)` **after Echo** and keeps the target
read direction open temporarily. Both one/two-Destination-
Options IPv6 fragment layouts are checked in each mode.
Chimera sends a server-first FIN in **all four** probes;
the pinned Xray 26.9.9 returns the Echo in all four but does
**not** emit TUN-side FIN during the bounded 3.2-second
server-first observation for either target close method.
The raw client then initiates its FIN, completes the handshake,
and successfully reuses the same four-tuple under a new ISN.
Hence the Xray path is **client-first**, not proof of gVisor
TIME_WAIT behavior. Source inspection confirms that the
Xray `tun.Handler` / `gonet.TCPConn` boundary uses
buffered Dispatcher/Freedom copy tasks; a downstream EOF
does not directly call `gonet.TCPConn.CloseWrite()`.

The vendored `active_ipv6_tcp_fin_timewait_duplicate_fin_and_same_tuple_reopen`
regression now covers **eight** combinations: default/Xray-opt-in
constructor × one/two IPv6 fragment chains × server-first
and client-first FIN. In the latter path the synthetic client
first sends a fragmented FIN, the server stream receives EOF,
then it can still write and close its own send direction.
Both orders require byte-exact data, a duplicate old FIN,
a genuinely old application-data replay, and fresh same-tuple
reconnection. This does not claim that local smoltcp behaves
like gVisor in the unexercised gVisor TIME_WAIT state.

The 14.16 pinned-Xray follow-up separates **downstream EOF from
Xray's terminal session ownership**. Its normal Freedom oracle
runs unchanged. After the full normal suite and device/route cleanup,
the test starts a **second pinned Xray 26.9.9 process** with a
test-only level-0 idle timeout of 2 seconds; this does not alter
normal Chimera or Xray TUN behavior or the existing long-stall
zero-window tests. The idle-policy probe includes close,
`shutdown(SHUT_WR)` and **keep-both-directions-open**
controls, each with one/two IPv6 extension-header chains.
All six still required client-first FIN before a completed
handshake despite up to 5.5 seconds to observe server FIN.
Thus neither downstream EOF nor the tested short-idle
policy produced an observed Xray **server-FIRST-FIN**.

The separate Xray-only `blackhole` outbound routes exactly
TCP destination port 39647 without dialing the Echo target.
The pinned `proxy/blackhole/blackhole.go` returns immediately
for a no-response TCP connection, causing the TUN handler's
deferred close through `gonet.TCPConn`. In two independent
valid raw IPv6 TCP handshakes the first direct comparison
observed **Xray server-FIRST-FIN, successful client FIN ACK
and a fresh ACK for a duplicate client FIN** after closure.
This is direct on-wire evidence for the pinned gVisor
`tcp/rcv.go` TIME_WAIT duplicate-FIN behavior, unlike
the client-first Freedom cases. An additional same-four-tuple
higher-ISN SYN is measured separately: the first exploratory
Blackhole flow returned **no SYN-ACK** in its bounded check.
That test was corrected to **require FIN/duplicate-FIN
correctness while reporting same-tuple reuse independently**,
rather than incorrectly treating refusal to reopen an
immediate no-response Blackhole flow as a failure of
TIME_WAIT FIN handling. Its test-only Xray
routing and policy are reset when the second process exits;
the namespace checks both the TUN device and IPv4/IPv6
route cleanup. A local vendored netstack regression already
covers both server-first and client-first FIN directions
across eight constructor/fragment-chain combinations; no
production TCP implementation was altered.

Keep the `tun-gateway` Cargo feature optional. When these commits become
available from a reproducible upstream ref, compare the complete `clash-netstack`
tree before replacing this snapshot; preserve the Server-side regression
coverage for shutdown and diagnostic redaction.

## Verification

The vendored base was compared with the Client checkout at
`8fc9b2b3821a571f806cda6cc4df68bef8ad1b46`; Client changes are retained and
the Server delta adds UDP source fragmentation, idle fragment-state expiry
scans, and their regression tests. The package tests pass: 20 unit tests and 61 integration tests, including
Xray-only unknown Destination Option actions, option-length and Hdr Ext Len / first-fragment header-chain boundaries, same-fragment-ID recovery, and strict-mode isolation.
The regression `tcp_blackhole_like_stream_close_obeys_xray_timewait_opt_in`
now checks four combinations: default/Xray-opt-in × direct stream Drop/
shutdown-then-Drop. Only Xray-opt-in sockets retain smoltcp's TIME-WAIT
state to ACK a duplicate FIN and prevent same-four-tuple SYN-ACK during
the 120 ms / 800 ms observation windows; default sockets continue to
omit the ACK and accept the new tuple immediately. One Xray-opt-in case
waits past the 10-second smoltcp close timer and verifies that the old
tuple can be admitted again. The Xray+shutdown case also injects a
checksum-valid in-window RST while in TIME-WAIT and confirms that it
cannot open a fresh incarnation. A separate `xray_timewait_burst_preserves_new_admission_and_recovers_on_expiry`
in-memory integration test opens and closes **32** independent TCP
four-tuples, verifies TIME-WAIT blocks an old tuple but permits a new
tuple, then checks expiry recovery and listener shutdown. These tests
are bounded functional probes, **not** a 512-concurrent-stream load or
sustained memory/CPU benchmark.

The vendor-specific implementation uses smoltcp 0.13.1's real
`State::TimeWait` rather than `is_active()` (which excludes that state).
It holds the state only for `new_with_mtu_xray_tun_compat`, reserves the
four-tuple in a shared packet-admission/socket-state set, forwards new
SYNs to the existing TIME-WAIT socket without creating a second listener,
and releases the reservation on timer expiry or socket-set panic recovery.
After verifying the incoming TCP checksum, the Xray-only packet pump also
silently drops an RST for a retained TIME-WAIT tuple, matching the pinned
gVisor `pkg/tcpip/transport/tcp/rcv.go` TIME-WAIT rule (RFC 1337),
without weakening established-state or default `tun-gateway` RST handling.
The existing `ACTIVE_TCP_STREAM_MAX = 512` cap counts retained socket
handles; normal service shutdown drops the TCP engine and reservation set.
Default `tun-gateway` retains its pre-existing behavior. The fixed Xray
26.9.9 Blackhole TCP/39647 reference ignored a checksum-valid post-close
fragmented RST (no new same-tuple SYN-ACK); the original Chimera path
reopened the tuple in that scenario. Xray negotiated TCP Timestamps for
the same probe but Chimera did not: reference acknowledgement of a
stale-TS FIN is an observation, not full PAWS equivalence. The wider
TIME-WAIT timer, RST edge cases, TCP Timestamp/PAWS and sustained
buffer-filled 512-stream pressure remain unverified. A separate
**explicitly ignored** integration test, `xray_tcp_512_active_socket_cap_and_rst_recovery`,
exercises the live Xray-opt-in TCP listener with 512 simultaneous
SYN-RECEIVED socket handles; the 513th SYN cannot create a new TCP
connection or accepted stream, and a valid established-state RST and
stream Drop release capacity for a fresh SYN. The test then checks
listener shutdown while many sockets are held. Run it explicitly via:

```sh
cargo test --manifest-path vendor/watfaq-netstack/Cargo.toml --test integration_test xray_tcp_512_active_socket_cap_and_rst_recovery -- --exact --ignored --nocapture
```

In a local development run it admitted 512 handles in about 142 ms;
the process reported ~16 MiB VmRSS because the large receive/send
buffers were not filled. Neither number is a production throughput or
worst-case memory measurement. The older 32-flow TIME-WAIT test
separately exercises FIN completion and timer expiry, not 512 simultaneous
TIME-WAIT sockets.

**Later Timestamp opt-in (2026-10-10):** the pinned Xray 26.9.9 SYN-ACK
negotiates TCP Timestamps. Its exact gVisor dependency explicitly says
`As we do not yet support PAWS` in `tcp/rcv.go` TIME-WAIT handling.
Xray's existing real TUN oracle accepts a fresh-sequence packet with an
older TSval (both normal and 32-bit wrapped), and may accept data when a
previously negotiated Timestamp is absent. Thus Timestamp negotiation
does *not* prove PAWS replay filtering in this fixed reference either.

Only `new_with_mtu_xray_tun_compat` now calls
`tcp::Socket::set_tsval_generator` before `listen()`. Its callback
uses monotonic milliseconds with a per-process random 32-bit offset;
smoltcp's function-pointer API cannot use a per-connection offset.
The default constructor continues to decline Timestamp, and Xray mode
also declines it when the peer SYN does not offer a Timestamp. The
renamed `established_ipv6_tcp_timestamp_negotiation_replay_and_recovery`
and new `xray_tcp_timestamp_negotiates_only_if_syn_offers_option` tests
verify SYN-ACK negotiation, TSecr, absent/available SYN options and
continued data integrity after an old-sequence replay. The real namespace
TCP Timestamp probe sees normal and wrapped fresh data and missing-TS
data delivered; old TCP sequence replays still do not duplicate app data.

**Subsequent TSecr recency correction (2026-10-10):** pinned gVisor's
`Endpoint::updateRecentTimestamp` uses signed 32-bit wrap-aware TSval
comparison and checks that the packet SEQ is no later than its cumulative
ACK. The Xray-only TCP packet pump now maintains recent TSval per accepted
Timestamp-enabled socket, keyed by TCP four-tuple and a weak socket owner;
expired owners are pruned at the 512-stream cap or on tuple reuse. After
**validating the original TCP checksum**, it normalizes an older incoming
TSval forwarded to smoltcp so the outgoing TSecr retains the newer value,
recomputing the TCP checksum without changing TCP sequence, flags or
payload. A conservative in-order sequence cursor approximates the pinned
ACK gate; this is not a complete reproduction of gVisor's ACK or PAWS
state machine. The earlier non-wrapped TSecr mismatch is resolved in the
bounded real-TUN oracle: both sides emit `[41000, 41000, 44000]` rather
than Chimera's previous `[41000, 40001, 44000]`; wrap case stays
`[4294967288, 8, 8, 56]`. Unit tests cover wrap and option truncation;
`xray_tcp_timestamp_tsecr_recent_is_not_regressed_by_older_data` covers
actual in-memory TCP data delivery and ACK TSecr. The packet pump state
is explicitly Xray-only and never changes default TUN. The local Timestamp
generator still has a per-process rather than gVisor per-connection offset.
**Follow-up out-of-order repair (2026-10-10):** the initial recency
cursor stalled when a missing TCP prefix arrived *after* a previously
received suffix. The Xray-only timestamp metadata now tracks up to 32
out-of-order ranges within the configured 256 KiB TCP receive buffer;
a repaired prefix absorbs adjacent buffered ranges, allowing later
contiguous new-TS data to advance TSecr. No payload is duplicated and
no default TUN path is changed. The helper regression first reproduced
`[1011,1021)` then `[1001,1011)` incorrectly yielding cursor 1011
instead of 1021; after correction, normal and 32-bit sequence wrap
cases pass. Future-sequence pure ACK and zero-length window-probe unit
controls do not advance the cursor. The real in-memory integration
`xray_tcp_tsecr_out_of_order_gap_repair_matches_ack_frontier` verifies
application delivery, cumulative ACK and TSecr through an actual gap;
the pinned Xray 26.9.9 Linux namespace test checks the same gap/frontier
against Chimera, requiring TSecr 45000 then 46000 on both. The separate
32-hole and 256-KiB bounds prevent metadata explosion under attack.
**Follow-up abnormal-ACK oracle (2026-10-10):** a new real Linux-TUN
probe against pinned Xray 26.9.9 sends a far-future TCP SEQ carrying
TSval=61000, then a valid fresh TSval=46010; a valid SEQ with an
impossible far-future ACK number carrying TSval=62000, then fresh
TSval=46020; and a client-advertised zero receive-window ACK plus
window reopen and fresh TSval=46040. Both pinned Xray and Chimera
produce TSecr **46010, 62000, 62000** on the new application echoes;
strict assertions now pin this reference behavior. The accepted-SEQuence
future ACK's TSval *does* update the reference's recency even though the
ACK number is impossible, consistent with gVisor's receive acceptability
check and sender timestamp update ordering. A focused in-memory Xray
TCP integration case verifies the corresponding far-seq/future-ACK
fresh-data recovery and TSecr; **no production code changed**.
Only the **client's advertised receive window** was zero here, not the
server's inbound receive buffer. **Later true server receive-zero-window
regression (2026-10-11):** an opt-in, ignored-by-default memory-TUN
integration test stops application TCP reads and fills both 256 KiB RX
buffers until a real outgoing server ACK advertises window zero (observed
at 524,280 accepted bytes with Window Scale 3). A zero-window 1-byte
probe with TSval=75000 is not ACKed. Previously, this rejected data
incorrectly poisoned the Xray-only timestamp helper: after reading
32 KiB, waiting for a genuine nonzero window update and retransmitting
with TSval=50000, the ACK returned TSecr=75000. The Xray-only packet
pump now consults a release/acquire atomic mirrored from the smoltcp
socket owner's *wire-advertised* zero-receive-window condition. Data/FIN
rejected at zero window cannot advance TSecr or the helper's SEQ; pure
ACKs remain separately eligible. The criterion matches smoltcp's
negotiated Window Scale quantum (8 free bytes at 256 KiB, 1 without
WS), not only a completely full socket ring. After the fix, the accepted
retransmission ACK had TSecr=50000; all original application bytes and
the retransmitted byte were read in order without leaking the rejected
probe. Run explicitly:

```sh
cargo test --manifest-path vendor/watfaq-netstack/Cargo.toml --test integration_test xray_tcp_actual_receive_zero_window_timestamp_probe -- --exact --ignored --nocapture
```

**Later pinned-binary oracle (2026-10-11):** the real Linux namespace
smoke has an explicit opt-in stalled-target TCP/39648 probe for the
*server* receive window, not the client's advertised window. It stops
reading from the downstream TCP connection, sends checksum-valid raw
IPv6 TCP with Timestamp and WS=3 while respecting the server's scaled
ACK window, detects and refills a transient zero-window state, and
requires a persistent advertised zero before sending a one-byte
TSval=75000 probe. After releasing the target's reads, it requires
a nonzero window update and an accepted retransmission with TSval=50000
and TSecr=50000. **Both Chimera and pinned Xray 26.9.9 passed:** stable
zero after **1,196,016** vs **1,048,320** bytes respectively (server
WS **3** vs **8**), rejected probe, window reopen and final TSecr
**50000**. Trigger with
`XRAY_TUN_SERVER_RX_PRESSURE=1 XRAY_BIN=./xray bash scripts/test_xray_tun_routes_netns.sh`.
The normal smoke skips this high-pressure oracle by default; it enforces
20 MiB/100 s pressure limits and retains strict failure on any incorrect
wire state. Some earlier iterations failed on incorrect SYN-option
encoding, a target timeout, or a transient initial zero window; those
negative development observations do not establish a gVisor defect.
**Follow-up adversarial zero-window oracle (2026-10-11):** the same
explicit paired stress fixture additionally sends four high-Timestamp,
single-byte data segments at a stable *server* zero receive window:
next expected SEQ=75000 TSval, a duplicate at that SEQ with 76000,
a future out-of-order byte at SEQ+8 with 77000, and overlap with the
previously acknowledged byte at SEQ-1 with 78000. All must leave the
cumulative ACK unchanged and must not poison the subsequent legitimate
TSval=50000 retransmission's **TSecr=50000**. After reopening the
window, the probe deliberately sends an out-of-order suffix TSval=85000,
repairs its gap with TSval=50010 (expected TSecr **50010**) and sends a
fresh contiguous byte TSval=50020 (expected TSecr **50020**). Both
Chimera and pinned Xray 26.9.9 passed the entire bounded wire sequence.
The ignored-by-default in-memory true-zero-window integration regression
also now checks these cases and byte-exact application delivery.
**Next paired loss-burst / independent-flow isolation oracle (2026-10-11):**
while the pressure TCP/39648 flow is held at a genuine zero server RX
window, **four distinct kernel-TCP connections** to the normal echo
TCP/39643 must complete concurrently with exact payloads; four **new**
independent flows must do so again after the pressure flow reopens.
The same pressure connection then processes five consecutive four-byte
chunks delivered out of order, indices **4, 2, 3, 1**, and receives
missing chunk 0 last. Before chunk 0, every server ACK must stay at the
unfilled prefix; the repaired cumulative ACK must echo TSecr **50010**
and a following new byte TSecr **50020**. Both Chimera and the pinned
Xray 26.9.9 passed these new, tightly bounded real-TUN assertions.
The ignored-by-default in-memory true-zero-window integration test
likewise checks the four-chunk reorder and verifies exact stream bytes.
**No production TCP code changed**; this is one pressured flow alongside
four *unpressured* independent concurrent streams, with deliberately
withheld/reordered input, **not** four simultaneous zero-window streams
or real stochastic network loss. Burst-loss retransmit timers are
outside this isolated single-pressure oracle.

**Two simultaneous zero-window server streams (2026-10-11):** the
explicit `XRAY_TUN_SERVER_RX_MULTISTALL=1 XRAY_BIN=./xray bash
scripts/test_xray_tun_routes_netns.sh` branch runs two independent raw
TCP clients (distinct source ports 46230/46231, nftables tables and
sequence spaces) for **each implementation**. A two-slot file barrier
keeps both downstream TCP application readers paused until both peers
have stably advertised a real zero receive window and each has passed
its own rejected-data and four independent live echo checks. Both then
recover their window and confirm TSecr **50000, 50010, 50020** across
legitimate retransmission, controlled four-chunk gap repair and new
data; each verifies four further independent echo connections after
reopening. In the paired real Linux-TUN test **both Chimera streams
passed**, each with server WS=3 and about 1.196 MiB accepted, and
**both pinned Xray 26.9.9 streams passed**, server WS=8 with about
0.999 MiB and 4.913 MiB accepted, respectively. The different Xray
per-flow byte thresholds are diagnostic, not hardcoded acceptance
criteria; the oracle checks the actual server ACK/window. All test
resources and the downstream release signal are properly scoped to
the cohort. The older single-stream opt-in and default smoke retain
their prior behavior; **no production TCP code changed**. More than
two simultaneous stalled streams, stochastic loss, sustained resource
exhaustion, receive-window autotuning and full PAWS remain **Partial**.
**Seeded real-packet-loss follow-up (2026-10-11):** new, explicitly
opted-in Linux TUN oracle `XRAY_TUN_SEEDED_NETEM=1` attaches `tc netem`
with `loss random 3% seed 31991` to the isolated Office-client veth
*only*. Four real kernel TCP/IPv6 connections to TCP/39643 each echo
128 KiB in 1 KiB blocks, verifying SHA-256 integrity, actual qdisc
drops and `TCP_INFO.tcpi_total_retrans > 0`, followed by qdisc removal
and a clean fresh echo. **Chimera and pinned Xray 26.9.9 passed**:
23/24 drops, respective retransmission vectors **[4,11,4,3]** and
**[4,6,3,11]**. Sender pacing differs, so the same seed does not imply
matching individual packet losses. The test is not enabled in ordinary
smoke; no production netstack code changed.

**8 KiB bulk-echo postmortem — fixed by the later Xray-only MSS clamp:**
the original *zero-loss* single 8 KiB write stalled on Chimera despite
the destination reading and echoing all 8192 bytes; 1 KiB chunks worked,
and switching the relay backend to userspace `copy` did not help.
Packet capture on the disposable TUN proved a missing **8040-byte TCP
sequence prefix**: smoltcp 0.13.1 chose six 1340-byte data segments as
if TCP had only a 20-byte base header, overlooking the negotiated 12-byte
Timestamp option. Its 1412-byte IPv6 packets exceeded the real 1400 MTU
and were discarded after the send sequence advanced. The earlier
in-memory 8 KiB case missed this because its test SYN omitted the
large Linux-style MSS. A new non-ignored test with **SYN MSS 1460 and
Timestamp** reproduced the exact 8040-byte gap, then passed after the
**Xray TUN-only internal SYN MSS clamp**, which reserves up to 40 bytes
for options without changing the actual MTU, outside-client SYN,
default `tun-gateway` or smoltcp dependency. At IPv6 MTU 1400 the
internal MSS is at most **1300**; live capture now verifies **six 1300-
byte segments plus a 392-byte tail**, full client echo and no gaps.
`XRAY_TUN_BULK_ECHO=1` pairs this independent single-write, zero-loss
8 KiB regression against Chimera and pinned Xray 26.9.9 in the real
namespace; the earlier 3%-loss oracle remains separately opt-in.
Exact congestion/MSS pacing and broad PAWS behavior remain **Partial**.

The package's
all-target/all-feature Clippy check passes with warnings denied:

```sh
cargo test --manifest-path vendor/watfaq-netstack/Cargo.toml
cargo clippy --manifest-path vendor/watfaq-netstack/Cargo.toml --all-targets --all-features -- -D warnings
```

The Server integration is separately covered by
`cargo test -p chimera_server_lib --no-default-features --features tun-gateway,vless-reverse --lib tun_gateway --locked`
(24 passed) and the single-site namespace smoke. The duplicate-LAN and Xray-edge
smoke scripts remain separate interoperability checks.
