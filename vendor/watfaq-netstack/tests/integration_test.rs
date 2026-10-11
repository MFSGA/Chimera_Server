use futures::{SinkExt, StreamExt};
use watfaq_netstack::{NetStack, Packet, UdpSocket};

mod common;
mod mock_tun;

use common::{
    build_tcp_ack, build_tcp_syn_packet, build_tcp_syn_packet_with_port,
    build_udp_packet, init, is_rst, is_syn_ack, parse_server_isn, parse_tcp_data,
    tcp_dst_port,
};
use mock_tun::MockTun;

fn build_ipv4_udp_fragments(payload: &[u8]) -> [Vec<u8>; 2] {
    let source = [1, 1, 1, 1];
    let destination = [2, 2, 2, 2];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv4(source, destination, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();
    let udp = &full[20..];
    let split = 16;

    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let mut header = etherparse::Ipv4Header::new(
            part.len() as u16,
            64,
            etherparse::ip_number::UDP,
            source,
            destination,
        )
        .unwrap();
        header.identification = 0x4242;
        header.dont_fragment = false;
        header.more_fragments = more_fragments;
        header.fragment_offset =
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap();
        header.header_checksum = header.calc_header_checksum();

        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(part);
        packet
    };

    [
        build(&udp[..split], 0, true),
        build(&udp[split..], split, false),
    ]
}

fn build_ipv6_udp_fragments(payload: &[u8]) -> [Vec<u8>; 2] {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();
    let udp = &full[40..];
    let split = 16;

    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let header = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + part.len())
                as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        };
        let fragment = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::UDP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more_fragments,
            0x1122_3344,
        );

        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(&fragment.to_bytes());
        packet.extend_from_slice(part);
        packet
    };

    [
        build(&udp[..split], 0, true),
        build(&udp[split..], split, false),
    ]
}

fn build_ipv4_tcp_syn_fragments() -> [Vec<u8>; 2] {
    let full = build_tcp_syn_packet();
    let tcp = &full[20..];
    let source = [1, 1, 1, 1];
    let destination = [2, 2, 2, 2];
    let split = 8;

    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let mut header = etherparse::Ipv4Header::new(
            part.len() as u16,
            64,
            etherparse::ip_number::TCP,
            source,
            destination,
        )
        .unwrap();
        header.identification = 0x5252;
        header.dont_fragment = false;
        header.more_fragments = more_fragments;
        header.fragment_offset =
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap();
        header.header_checksum = header.calc_header_checksum();

        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(part);
        packet
    };

    [
        build(&tcp[..split], 0, true),
        build(&tcp[split..], split, false),
    ]
}

fn build_ipv6_tcp_syn_fragments() -> [Vec<u8>; 2] {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .tcp(1234, 80, 0, 65535)
        .syn()
        .write(&mut full, &[])
        .unwrap();
    let tcp = &full[40..];
    let split = 8;

    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let header = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + part.len())
                as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        };
        let fragment = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::TCP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more_fragments,
            0x5566_7788,
        );

        let mut packet = header.to_bytes().to_vec();
        packet.extend_from_slice(&fragment.to_bytes());
        packet.extend_from_slice(part);
        packet
    };

    [
        build(&tcp[..split], 0, true),
        build(&tcp[split..], split, false),
    ]
}

fn build_ipv4_icmp_echo_fragments() -> [Vec<u8>; 2] {
    let source = [10, 0, 0, 2];
    let destination = [10, 0, 0, 1];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv4(source, destination, 64)
        .icmpv4_echo_request(7, 9)
        .write(&mut full, b"fragmented-icmpv4-odd")
        .unwrap();
    let icmp = &full[20..];
    let split = 16;
    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let mut header = etherparse::Ipv4Header::new(
            part.len() as u16,
            64,
            etherparse::ip_number::ICMP,
            source,
            destination,
        )
        .unwrap();
        header.identification = 0x6262;
        header.dont_fragment = false;
        header.more_fragments = more_fragments;
        header.fragment_offset =
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap();
        header.header_checksum = header.calc_header_checksum();
        [header.to_bytes().as_slice(), part].concat()
    };
    [
        build(&icmp[..split], 0, true),
        build(&icmp[split..], split, false),
    ]
}

fn build_ipv6_icmp_echo_fragments() -> [Vec<u8>; 2] {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .icmpv6_echo_request(7, 9)
        .write(&mut full, b"fragmented-icmpv6-echo")
        .unwrap();
    let icmp = &full[40..];
    let split = 16;
    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let header = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + part.len())
                as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        };
        let fragment = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::IPV6_ICMP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more_fragments,
            0x6677_8899,
        );
        [
            header.to_bytes().as_slice(),
            fragment.to_bytes().as_slice(),
            part,
        ]
        .concat()
    };
    [
        build(&icmp[..split], 0, true),
        build(&icmp[split..], split, false),
    ]
}

fn build_ipv6_icmp_echo_fragments_with_padding_hop_by_hop() -> [Vec<u8>; 2] {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .icmpv6_echo_request(7, 10)
        .write(&mut full, b"fragmented-icmpv6-hbh")
        .unwrap();
    let icmp = &full[40..];
    let hop_by_hop = [
        etherparse::ip_number::IPV6_FRAG.0,
        0, // 8-byte extension header.
        1,
        4,
        0,
        0,
        0,
        0, // PadN with four zero bytes.
    ];
    let split = 16;
    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let header = etherparse::Ipv6Header {
            payload_length: (hop_by_hop.len()
                + etherparse::Ipv6FragmentHeader::LEN
                + part.len()) as u16,
            next_header: etherparse::ip_number::IPV6_HOP_BY_HOP,
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        };
        let fragment = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::IPV6_ICMP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more_fragments,
            0x6677_889A,
        );
        [
            header.to_bytes().as_slice(),
            hop_by_hop.as_slice(),
            fragment.to_bytes().as_slice(),
            part,
        ]
        .concat()
    };
    [
        build(&icmp[..split], 0, true),
        build(&icmp[split..], split, false),
    ]
}

fn build_ipv6_icmp_echo_fragments_with_padding_destination_options() -> [Vec<u8>; 2]
{
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .icmpv6_echo_request(7, 11)
        .write(&mut full, b"fragmented-icmpv6-dst")
        .unwrap();

    // Fragment -> Destination Options -> ICMPv6: the extension belongs to
    // the fragmentable payload and is reassembled before being parsed.
    let destination_options = [
        etherparse::ip_number::IPV6_ICMP.0,
        0, // 8-byte extension header.
        1,
        4,
        0,
        0,
        0,
        0, // PadN with four zero bytes.
    ];
    let fragmentable = [destination_options.as_slice(), &full[40..]].concat();
    let split = 16;
    let build = |part: &[u8], offset: usize, more_fragments: bool| {
        let header = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + part.len())
                as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        };
        let fragment = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::IPV6_DEST_OPTIONS,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more_fragments,
            0x6677_889B,
        );
        [
            header.to_bytes().as_slice(),
            fragment.to_bytes().as_slice(),
            part,
        ]
        .concat()
    };
    [
        build(&fragmentable[..split], 0, true),
        build(&fragmentable[split..], split, false),
    ]
}

fn build_ipv6_icmp_echo_fragments_with_unknown_destination_option(
    option_type: u8,
) -> [Vec<u8>; 2] {
    build_ipv6_icmp_echo_fragments_with_destination_option_length(
        option_type,
        2,
        [0x4a, 0x62, 0, 0],
    )
}

fn build_ipv6_icmp_echo_fragments_with_destination_option_length(
    option_type: u8,
    option_length: u8,
    option_data: [u8; 4],
) -> [Vec<u8>; 2] {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .icmpv6_echo_request(7, 12)
        .write(&mut full, b"fragmented-icmpv6-unknown")
        .unwrap();
    let option = [
        etherparse::ip_number::IPV6_ICMP.0,
        0, // 8-byte Destination Options header
        option_type,
        option_length,
        option_data[0],
        option_data[1],
        option_data[2],
        option_data[3], // Padding only when option_length permits it
    ];
    let fragmentable = [option.as_slice(), &full[40..]].concat();
    let split = 16;
    let build = |part: &[u8], offset: usize, more: bool| {
        let header = etherparse::Ipv6Header {
            payload_length: (etherparse::Ipv6FragmentHeader::LEN + part.len())
                as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source,
            destination,
            ..Default::default()
        };
        let fragment = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::IPV6_DEST_OPTIONS,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more,
            0x6677_889c,
        );
        [
            header.to_bytes().as_slice(),
            fragment.to_bytes().as_slice(),
            part,
        ]
        .concat()
    };
    [
        build(&fragmentable[..split], 0, true),
        build(&fragmentable[split..], split, false),
    ]
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        let high = u32::from(word[0]) << 8;
        let low = word.get(1).copied().map(u32::from).unwrap_or_default();
        sum += high | low;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn is_any_ip_syn_ack(packet: &[u8]) -> bool {
    matches!(
        etherparse::SlicedPacket::from_ip(packet)
            .ok()
            .and_then(|packet| packet.transport),
        Some(etherparse::TransportSlice::Tcp(tcp)) if tcp.syn() && tcp.ack()
    )
}

#[tokio::test]
async fn test_stack_with_mock_tun_real_tcp_udp() {
    init();

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from mock_tun to stack_sink (TUN -> NetStack)
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            let packet = Packet::new(pkt);
            stack_sink.send(packet).await.unwrap();
        }
    });

    // Send a TCP SYN packet
    let tcp_syn = build_tcp_syn_packet();
    tun_in.send(tcp_syn.clone()).unwrap();

    log::info!("Sent TCP SYN and UDP packets to mock TUN");

    let Some(Ok(reply)) = stack_stream.next().await else {
        panic!("No packets received from stack");
    };

    assert!(is_syn_ack(reply.data()));
    log::info!("Received TCP SYN-ACK packet from stack");

    let stream = tcp_listener.next().await.unwrap();
    log::info!("Accepted TCP stream: {:?}", stream);
    assert_eq!(stream.local_addr(), "1.1.1.1:1024".parse().unwrap());
    assert_eq!(stream.remote_addr(), "2.2.2.2:80".parse().unwrap());

    // Send a UDP packet
    let udp_pkt = build_udp_packet();
    tun_in.send(udp_pkt.clone()).unwrap();

    log::info!("Sent UDP packet to mock TUN");
    let (mut udp_read, _) = udp_socket.split();
    let Some(udp_packet) = udp_read.recv().await else {
        panic!("No UDP packet received");
    };
    assert_eq!(udp_packet.local_addr, "1.1.1.1:5000".parse().unwrap());
    assert_eq!(udp_packet.remote_addr, "2.2.2.2:5001".parse().unwrap());
}

/// Verifies that a relay can sustain a 16 MB bulk TCP transfer through the
/// netstack without stalling. A relay task writes into the netstack TcpStream
/// while a simulated client reads segments from StackSplitStream and sends
/// cumulative ACKs back. The test fails if throughput stalls for more than
/// 5 seconds or the whole transfer exceeds 30 s.
///
/// This catches the regression where poll_sockets runs in a tight loop and
/// starves StackSplitStream, blocking the consumer from draining the tx channel
/// and sending ACKs, which fills smoltcp's send window and triggers RTO.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_speedtest_bulk_download() {
    init();

    const TRANSFER_BYTES: usize = 16 * 1024 * 1024; // 16 MB

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward packets from the mock TUN into the netstack.
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // Client simulation task: performs the TCP handshake, reads data segments
    // from StackSplitStream, and sends cumulative ACKs back through the mock TUN.
    // Spawned before awaiting tcp_listener so its SYN is in-flight while we wait.
    let client = tokio::spawn(async move {
        tun_in.send(build_tcp_syn_packet()).unwrap();

        let server_isn = loop {
            let pkt = stack_stream
                .next()
                .await
                .expect("stack_stream closed")
                .expect("stack_stream error");
            if is_syn_ack(pkt.data()) {
                break parse_server_isn(pkt.data());
            }
        };

        // SYN consumed client seq=0, so client_seq after handshake = 1.
        let client_seq: u32 = 1;
        // cumulative_ack tracks the highest contiguous byte acknowledged from
        // the server, starting just past the SYN-ACK's sequence number.
        let mut cumulative_ack = server_isn.wrapping_add(1);
        tun_in
            .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
            .unwrap();

        // Receive bulk data and ACK each segment.
        let mut received = 0usize;
        let start = std::time::Instant::now();
        let mut last_check = start;
        let mut bytes_since_check = 0usize;

        while received < TRANSFER_BYTES {
            let pkt = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stack_stream.next(),
            )
            .await
            .expect("STALL: no TCP segment received for 5 s")
            .expect("stack_stream closed")
            .expect("stack_stream error");

            if let Some((seq, payload_len)) = parse_tcp_data(pkt.data()) {
                if payload_len > 0 {
                    let end_seq = seq.wrapping_add(payload_len as u32);
                    let advance = end_seq.wrapping_sub(cumulative_ack);
                    if advance > 0 && advance < (1u32 << 31) {
                        received += advance as usize;
                        bytes_since_check += advance as usize;
                        cumulative_ack = end_seq;
                    }
                    tun_in
                        .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
                        .unwrap();
                }
            } else {
                let _ = pkt;
            }

            let now = std::time::Instant::now();
            if now.duration_since(last_check) >= std::time::Duration::from_secs(1) {
                let mb = bytes_since_check as f64 / (1024.0 * 1024.0);
                eprintln!(
                    "[bulk] {:.1} MB/s  ({}/{} KB)",
                    mb,
                    received / 1024,
                    TRANSFER_BYTES / 1024,
                );
                bytes_since_check = 0;
                last_check = now;
            }
        }

        let elapsed = start.elapsed();
        let throughput = received as f64 / elapsed.as_secs_f64() / (1024.0 * 1024.0);
        eprintln!(
            "[bulk] done: {} KB in {:.2}s = {:.1} MB/s",
            received / 1024,
            elapsed.as_secs_f64(),
            throughput,
        );
        received
    });

    // Await the TcpStream here, not inside the relay task. This keeps
    // tcp_listener alive until after join!() completes, preventing
    // TcpListener::Drop from aborting the netstack task while data is in-flight.
    let stream = tcp_listener.next().await.expect("no TcpStream");

    // Relay task: writes TRANSFER_BYTES into the TcpStream.
    let relay = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;

        let mut stream = stream;
        let chunk = vec![0xABu8; 16 * 1024]; // 16 KB chunks
        let mut written = 0usize;
        while written < TRANSFER_BYTES {
            let n = (TRANSFER_BYTES - written).min(chunk.len());
            stream
                .write_all(&chunk[..n])
                .await
                .expect("write_all failed");
            written += n;
        }
        written
    });

    let (relay_res, client_res) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::join!(relay, client)
        })
        .await
        .expect("Test timed out (30 s) - likely a stall in the netstack");

    // tcp_listener is dropped here, after relay and client both complete.
    drop(tcp_listener);

    assert_eq!(relay_res.unwrap(), TRANSFER_BYTES);
    assert_eq!(client_res.unwrap(), TRANSFER_BYTES);
}

/// Verifies that a new TCP connection gets a SYN-ACK (not RST) while another
/// connection is actively bulk-transferring data.
///
/// Bug B root cause: poll_sockets only drained notifier_rx in the else branch,
/// which was skipped whenever should_poll_now = true. During an active
/// download, poll_delay near zero keeps should_poll_now = true permanently, so
/// new IfaceEvent::TcpStream events were never consumed before iface.poll() ran.
/// smoltcp saw the incoming SYN with no matching socket and replied with RST.
///
/// Fix: drain notifier_rx with try_recv() before every iface.poll() call.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_new_connection_during_active_transfer() {
    init();

    use tokio::sync::mpsc;

    const CONN1_BYTES: usize = 4 * 1024 * 1024; // 4 MB keeps smoltcp in hot path.

    let (mut mock_tun, tun_in, _) = MockTun::new();
    let (stack, mut tcp_listener, _udp) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // Forward mock TUN packets into the netstack.
    tokio::spawn(async move {
        while let Some(pkt) = mock_tun.next().await {
            stack_sink.send(Packet::new(pkt)).await.unwrap();
        }
    });

    // Per-connection demultiplexer: routes outbound smoltcp packets to each
    // simulated client by TCP destination port (= client's source port).
    let (tx1, mut rx1) = mpsc::unbounded_channel::<Packet>();
    let (tx2, mut rx2) = mpsc::unbounded_channel::<Packet>();
    tokio::spawn(async move {
        while let Some(Ok(pkt)) = stack_stream.next().await {
            match tcp_dst_port(pkt.data()) {
                Some(1024) => {
                    let _ = tx1.send(pkt);
                }
                Some(1025) => {
                    let _ = tx2.send(pkt);
                }
                _ => {}
            }
        }
    });

    // Oneshot: conn1 client signals conn2 client once data is flowing.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let tun_in2 = tun_in.clone();

    // Client 1 (port 1024): handshake + receive CONN1_BYTES, ACKing each segment.
    let client1 = tokio::spawn(async move {
        tun_in.send(build_tcp_syn_packet()).unwrap();

        let server_isn = loop {
            let pkt = rx1.recv().await.expect("rx1 closed before SYN-ACK");
            if is_syn_ack(pkt.data()) {
                break parse_server_isn(pkt.data());
            }
        };
        let client_seq: u32 = 1;
        let mut cumulative_ack = server_isn.wrapping_add(1);
        tun_in
            .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
            .unwrap();

        let mut received = 0usize;
        let mut signalled = false;
        let mut ready_tx = Some(ready_tx);

        while received < CONN1_BYTES {
            let pkt =
                tokio::time::timeout(std::time::Duration::from_secs(5), rx1.recv())
                    .await
                    .expect("conn1 stalled for 5 s")
                    .expect("rx1 closed");

            if let Some((seq, payload_len)) = parse_tcp_data(pkt.data())
                && payload_len > 0
            {
                let end_seq = seq.wrapping_add(payload_len as u32);
                let advance = end_seq.wrapping_sub(cumulative_ack);
                if advance > 0 && advance < (1u32 << 31) {
                    received += advance as usize;
                    cumulative_ack = end_seq;
                }
                tun_in
                    .send(build_tcp_ack(client_seq, cumulative_ack, u16::MAX))
                    .unwrap();
                // Signal conn2 client on the first received data segment.
                if !signalled {
                    signalled = true;
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(());
                    }
                }
            }
        }
        received
    });

    // Client 2 (port 1025): waits until conn1 is actively transferring, then
    // sends a SYN and asserts it receives a SYN-ACK, not RST or timeout.
    let client2 = tokio::spawn(async move {
        ready_rx
            .await
            .expect("ready signal lost - conn1 relay never started");

        tun_in2.send(build_tcp_syn_packet_with_port(1025)).unwrap();

        // Expect SYN-ACK within 5 s. Without the drain-loop fix smoltcp
        // responds with RST or the packet is silently dropped.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let pkt = rx2.recv().await.expect("rx2 closed before SYN-ACK");
                if is_syn_ack(pkt.data()) {
                    return;
                }
                if is_rst(pkt.data()) {
                    panic!(
                        "connection 2 received RST - Bug B not fixed (drain \
                         notifier_rx before iface.poll() is missing)"
                    );
                }
            }
        })
        .await
        .expect("timed out waiting for SYN-ACK on connection 2 - Bug B not fixed");
    });

    // Accept conn1.
    let stream1 = tcp_listener.next().await.expect("no stream for conn1");

    // Relay 1: write CONN1_BYTES so smoltcp stays in the hot path long enough
    // for conn2's SYN to arrive.
    let relay1 = tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;

        let mut stream = stream1;
        let chunk = vec![0u8; 16 * 1024];
        let mut written = 0usize;
        while written < CONN1_BYTES {
            let n = (CONN1_BYTES - written).min(chunk.len());
            stream
                .write_all(&chunk[..n])
                .await
                .expect("relay1 write failed");
            written += n;
        }
        written
    });

    // Accept conn2.
    let stream2 = tcp_listener.next().await.expect("no stream for conn2");
    drop(stream2);

    let (relay1_res, client1_res, client2_res) =
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            tokio::join!(relay1, client1, client2)
        })
        .await
        .expect("test timed out (30 s)");

    drop(tcp_listener);

    assert_eq!(relay1_res.unwrap(), CONN1_BYTES, "relay1 bytes mismatch");
    assert_eq!(client1_res.unwrap(), CONN1_BYTES, "client1 bytes mismatch");
    client2_res.unwrap(); // panics if client2 saw RST or timed out
}

#[tokio::test]
async fn malformed_ip_does_not_fail_stack_sink() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    stack_sink
        .send(Packet::new(vec![0x45, 0x00, 0x00]))
        .await
        .expect("malformed IP packet must be dropped, not fail the stack sink");
    stack_sink
        .send(Packet::new(build_udp_packet()))
        .await
        .unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("valid UDP packet was not delivered after malformed IP input")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.local_addr, "1.1.1.1:5000".parse().unwrap());
}

#[tokio::test]
async fn malformed_udp_does_not_end_receive_stream() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    let mut malformed = build_udp_packet().to_vec();
    malformed[24..26].copy_from_slice(&7_u16.to_be_bytes());
    stack_sink.send(Packet::new(malformed)).await.unwrap();
    stack_sink
        .send(Packet::new(build_udp_packet()))
        .await
        .unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("valid UDP packet was not delivered after malformed input")
            .expect("UDP receive stream ended after malformed input");

    assert_eq!(packet.local_addr, "1.1.1.1:5000".parse().unwrap());
    assert_eq!(packet.remote_addr, "2.2.2.2:5001".parse().unwrap());
}

#[tokio::test]
async fn zero_length_udp_is_emitted() {
    let (_input_tx, input_rx) = tokio::sync::mpsc::channel(8);
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(1);
    let (_reader, mut writer) = UdpSocket::new(input_rx, output_tx).split();

    writer
        .send(
            (
                Vec::<u8>::new(),
                "1.1.1.1:5000".parse().unwrap(),
                "2.2.2.2:5001".parse().unwrap(),
            )
                .into(),
        )
        .await
        .unwrap();

    let packet = output_rx
        .recv()
        .await
        .expect("zero-length UDP datagram was not emitted");
    assert_eq!(packet.data().len(), 28);
}

async fn assert_large_udp_output_is_fragmented_and_reassembles(
    source: std::net::SocketAddr,
    destination: std::net::SocketAddr,
    mtu: usize,
) {
    let (input_tx, input_rx) = tokio::sync::mpsc::channel(8);
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(8);
    let (mut udp_read, mut udp_write) =
        UdpSocket::new_with_mtu(input_rx, output_tx, mtu)
            .unwrap()
            .split();
    let payload = vec![0x5a; 4096];

    udp_write
        .send((payload.clone(), source, destination).into())
        .await
        .unwrap();

    let mut fragments = Vec::new();
    while let Ok(packet) = output_rx.try_recv() {
        assert!(
            packet.data().len() <= mtu,
            "UDP output exceeded the TUN MTU"
        );
        fragments.push(packet);
    }
    assert!(
        fragments.len() > 1,
        "oversized UDP output was not fragmented"
    );

    // Reverse order exercises reassembly rather than relying on arrival order.
    for fragment in fragments.into_iter().rev() {
        input_tx.send(fragment).await.unwrap();
    }
    let received =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("fragmented UDP output did not reassemble")
            .expect("UDP reader closed unexpectedly");

    assert_eq!(received.data(), payload);
    assert_eq!(received.local_addr, source);
    assert_eq!(received.remote_addr, destination);
}

#[tokio::test]
async fn oversized_ipv4_udp_output_is_fragmented_for_the_device_mtu() {
    assert_large_udp_output_is_fragmented_and_reassembles(
        "10.254.0.1:53000".parse().unwrap(),
        "10.44.0.20:39642".parse().unwrap(),
        1500,
    )
    .await;
}

#[tokio::test]
async fn oversized_ipv6_udp_output_is_fragmented_for_the_device_mtu() {
    assert_large_udp_output_is_fragmented_and_reassembles(
        "[fd00:254::1]:53000".parse().unwrap(),
        "[2001:db8:44::20]:39642".parse().unwrap(),
        1500,
    )
    .await;
}

#[tokio::test]
async fn oversized_ipv4_udp_output_is_fragmented_to_configured_1280_mtu() {
    assert_large_udp_output_is_fragmented_and_reassembles(
        "10.254.0.1:53000".parse().unwrap(),
        "10.44.0.20:39642".parse().unwrap(),
        1280,
    )
    .await;
}

#[tokio::test]
async fn oversized_ipv6_udp_output_is_fragmented_to_configured_1280_mtu() {
    assert_large_udp_output_is_fragmented_and_reassembles(
        "[fd00:254::1]:53000".parse().unwrap(),
        "[2001:db8:44::20]:39642".parse().unwrap(),
        1280,
    )
    .await;
}

#[tokio::test]
async fn netstack_rejects_mtu_outside_ip_and_ipv6_bounds() {
    for mtu in [0, 1279, u16::MAX as usize + 1] {
        let result = NetStack::new_with_mtu(mtu);
        assert!(result.is_err(), "unexpectedly accepted MTU {mtu}");
    }
}

#[tokio::test]
async fn full_udp_packet_queue_drops_all_fragments_atomically() {
    let (_input_tx, input_rx) = tokio::sync::mpsc::channel(8);
    let (output_tx, mut output_rx) = tokio::sync::mpsc::channel(1);
    let (_udp_read, mut udp_write) = UdpSocket::new(input_rx, output_tx).split();

    udp_write
        .send(
            (
                vec![0x7b; 4096],
                "10.254.0.1:53000".parse().unwrap(),
                "10.44.0.20:39642".parse().unwrap(),
            )
                .into(),
        )
        .await
        .expect("a full UDP output queue should drop without blocking");

    assert!(
        output_rx.try_recv().is_err(),
        "a subset of fragments must not escape when the queue cannot reserve the datagram"
    );
}

#[tokio::test]
async fn stack_sink_consecutive_feed_calls_make_progress() {
    let (stack, _tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();

    stack_sink
        .feed(Packet::new(build_udp_packet()))
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_sink.feed(Packet::new(build_udp_packet())),
    )
    .await
    .expect("second feed blocked without making progress")
    .unwrap();
    stack_sink.flush().await.unwrap();
}

#[tokio::test]
async fn stack_sink_backpressure_wakes_after_udp_queue_drains() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    for _ in 0..4096 {
        stack_sink
            .send(Packet::new(build_udp_packet()))
            .await
            .unwrap();
    }

    let blocked = stack_sink.send(Packet::new(build_udp_packet()));
    tokio::pin!(blocked);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut blocked)
            .await
            .is_err(),
        "bounded stack input queue did not apply backpressure"
    );

    udp_read.recv().await.expect("queued UDP packet missing");
    tokio::time::timeout(std::time::Duration::from_millis(300), blocked)
        .await
        .expect("stack sink was not woken after queue capacity became available")
        .unwrap();
}

#[tokio::test]
async fn stack_sink_reports_closed_udp_receiver() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    drop(udp_socket);

    let err = stack_sink
        .send(Packet::new(build_udp_packet()))
        .await
        .expect_err("closed UDP receiver must be reported to the sink");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn listener_drop_closes_existing_stream_io() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (stack, mut tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    stack_sink
        .send(Packet::new(build_tcp_syn_packet()))
        .await
        .unwrap();

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tcp_listener.next(),
    )
    .await
    .expect("TCP stream was not created")
    .expect("TCP listener ended unexpectedly");

    drop(tcp_listener);

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stream.read(&mut byte),
    )
    .await
    .expect("stream read remained pending after listener shutdown")
    .unwrap();
    assert_eq!(read, 0, "listener shutdown should surface EOF");

    let err = stream
        .write(b"x")
        .await
        .expect_err("write succeeded after TCP engine shutdown");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn listener_shutdown_waits_for_engine_and_closes_existing_stream_io() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (stack, mut tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    stack_sink
        .send(Packet::new(build_tcp_syn_packet()))
        .await
        .unwrap();

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tcp_listener.next(),
    )
    .await
    .expect("TCP stream was not created")
    .expect("TCP listener ended unexpectedly");

    tcp_listener
        .shutdown()
        .await
        .expect("TCP engine shutdown failed");
    tcp_listener
        .shutdown()
        .await
        .expect("repeated TCP engine shutdown should be harmless");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(300),
            tcp_listener.next(),
        )
        .await
        .expect("TCP accept stream did not close")
        .is_none()
    );

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stream.read(&mut byte),
    )
    .await
    .expect("stream read remained pending after listener shutdown")
    .unwrap();
    assert_eq!(read, 0, "listener shutdown should surface EOF");

    let err = stream
        .write(b"x")
        .await
        .expect_err("write succeeded after TCP engine shutdown");
    assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
}

#[tokio::test]
async fn invalid_tcp_checksum_does_not_create_stream() {
    let (stack, mut tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let mut packet = build_tcp_syn_packet().to_vec();
    packet[36] ^= 0xff;

    stack_sink.send(Packet::new(packet)).await.unwrap();

    let accepted = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tcp_listener.next(),
    )
    .await;
    assert!(
        accepted.is_err(),
        "invalid TCP checksum created an application stream"
    );
}

#[tokio::test]
async fn ipv6_hop_by_hop_udp_is_delivered() {
    let mut packet = Vec::new();
    etherparse::PacketBuilder::ipv6([0x20; 16], [0x21; 16], 64)
        .udp(1234, 4321)
        .write(&mut packet, b"test")
        .unwrap();
    packet[6] = 0;
    packet.splice(40..40, [17, 0, 0, 0, 0, 0, 0, 0]);
    let payload_len = (packet.len() - 40) as u16;
    packet[4..6].copy_from_slice(&payload_len.to_be_bytes());

    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();
    stack_sink.send(Packet::new(packet)).await.unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("IPv6 UDP behind Hop-by-Hop header was not delivered")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.data(), b"test");
}

#[tokio::test]
async fn icmp_echo_reply_works_without_tcp_socket() {
    let mut packet = Vec::new();
    etherparse::PacketBuilder::ipv4([10, 0, 0, 2], [10, 0, 0, 1], 64)
        .icmpv4_echo_request(1, 1)
        .write(&mut packet, b"ping")
        .unwrap();

    let (stack, _tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();
    stack_sink.send(Packet::new(packet)).await.unwrap();

    let reply = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_stream.next(),
    )
    .await
    .expect("ICMP echo reply timed out")
    .expect("stack output ended unexpectedly")
    .expect("stack returned an error");
    let ihl = ((reply.data()[0] & 0x0f) as usize) * 4;
    assert_eq!(reply.data()[9], 1);
    assert_eq!(reply.data()[ihl], 0, "expected ICMP Echo Reply");
}

#[tokio::test]
async fn unknown_ip_protocols_return_family_specific_icmp_errors() {
    let source_v4 = [10, 0, 0, 2];
    let destination_v4 = [10, 0, 0, 1];
    let mut ipv4 = etherparse::Ipv4Header::new(
        8,
        64,
        etherparse::IpNumber(252),
        source_v4,
        destination_v4,
    )
    .unwrap();
    ipv4.header_checksum = ipv4.calc_header_checksum();
    let mut ipv4_packet = ipv4.to_bytes().to_vec();
    ipv4_packet.extend_from_slice(&[0; 8]);

    let source_v6 = [0x20; 16];
    let destination_v6 = [0x21; 16];
    let ipv6 = etherparse::Ipv6Header {
        payload_length: 8,
        next_header: etherparse::IpNumber(252),
        hop_limit: 64,
        source: source_v6,
        destination: destination_v6,
        ..Default::default()
    };
    let mut ipv6_packet = ipv6.to_bytes().to_vec();
    ipv6_packet.extend_from_slice(&[0; 8]);

    let (stack, _tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();
    stack_sink.send(Packet::new(ipv4_packet)).await.unwrap();
    let ipv4_reply = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_stream.next(),
    )
    .await
    .expect("IPv4 protocol-unreachable response timed out")
    .expect("stack output ended unexpectedly")
    .expect("stack returned an error");
    assert_eq!(ipv4_reply.data()[9], etherparse::ip_number::ICMP.0);
    let ipv4_header_len = ((ipv4_reply.data()[0] & 0x0f) as usize) * 4;
    assert_eq!(ipv4_reply.data()[ipv4_header_len], 3);
    assert_eq!(ipv4_reply.data()[ipv4_header_len + 1], 2);
    assert_eq!(&ipv4_reply.data()[12..16], &destination_v4);
    assert_eq!(&ipv4_reply.data()[16..20], &source_v4);

    stack_sink.send(Packet::new(ipv6_packet)).await.unwrap();
    let ipv6_reply = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_stream.next(),
    )
    .await
    .expect("IPv6 unrecognized-next-header response timed out")
    .expect("stack output ended unexpectedly")
    .expect("stack returned an error");
    assert_eq!(ipv6_reply.data()[6], etherparse::ip_number::IPV6_ICMP.0);
    assert_eq!(ipv6_reply.data()[40], 4);
    assert_eq!(ipv6_reply.data()[41], 1);
    assert_eq!(&ipv6_reply.data()[8..24], &destination_v6);
    assert_eq!(&ipv6_reply.data()[24..40], &source_v6);
}

#[tokio::test]
async fn fragmented_ipv4_icmp_echo_reassembles_out_of_order() {
    let [first, second] = build_ipv4_icmp_echo_fragments();
    let (stack, _tcp, _udp) = NetStack::new();
    let (mut sink, mut output) = stack.split();
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();

    let reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect("fragmented ICMPv4 Echo Reply timed out")
            .expect("stack output closed")
            .expect("stack error");
    let header_length = usize::from(reply.data()[0] & 0x0f) * 4;
    let packet = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
    assert!(matches!(
        packet.transport,
        Some(etherparse::TransportSlice::Icmpv4(icmp))
            if matches!(icmp.icmp_type(), etherparse::Icmpv4Type::EchoReply(_))
    ));
    let message = &reply.data()[header_length..];
    assert_eq!(&message[8..], b"fragmented-icmpv4-odd");
    assert_eq!(internet_checksum(message), 0);
}

#[tokio::test]
async fn fragmented_ipv4_icmp_echo_checksum_compatibility_is_opt_in() {
    let [mut first, second] = build_ipv4_icmp_echo_fragments();
    first[22] ^= 0x01;

    let (stack, _tcp, _udp) = NetStack::new();
    let (mut sink, mut output) = stack.split();
    sink.send(Packet::new(second.clone())).await.unwrap();
    sink.send(Packet::new(first.clone())).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), output.next())
            .await
            .is_err(),
        "the default stack must keep rejecting invalid ICMPv4 checksums"
    );

    let (stack, _tcp, _udp) =
        NetStack::new_with_mtu_accepting_invalid_ipv4_icmp_echo_checksum(1500)
            .expect("Xray-compatible stack should be constructed");
    let (mut sink, mut output) = stack.split();
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();

    let reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect("fragmented invalid-checksum Echo Reply timed out")
            .expect("stack output closed")
            .expect("stack error");
    let header_length = usize::from(reply.data()[0] & 0x0f) * 4;
    let packet = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
    assert!(matches!(
        packet.transport,
        Some(etherparse::TransportSlice::Icmpv4(icmp))
            if matches!(icmp.icmp_type(), etherparse::Icmpv4Type::EchoReply(_))
    ));
    let message = &reply.data()[header_length..];
    assert_eq!(&message[8..], b"fragmented-icmpv4-odd");
    assert_eq!(internet_checksum(message), 0);

    let [mut first_ipv6, second_ipv6] = build_ipv6_icmp_echo_fragments();
    first_ipv6[50] ^= 0x01;
    sink.send(Packet::new(second_ipv6)).await.unwrap();
    sink.send(Packet::new(first_ipv6)).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), output.next())
            .await
            .is_err(),
        "Xray IPv4 checksum compatibility must not accept an invalid IPv6 checksum"
    );
}

#[tokio::test]
async fn fragmented_ipv6_icmp_echo_reassembles_out_of_order() {
    let [first, second] = build_ipv6_icmp_echo_fragments();
    let (stack, _tcp, _udp) = NetStack::new();
    let (mut sink, mut output) = stack.split();
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();

    let reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect("fragmented ICMPv6 Echo Reply timed out")
            .expect("stack output closed")
            .expect("stack error");
    let packet = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
    assert!(matches!(
        packet.transport,
        Some(etherparse::TransportSlice::Icmpv6(icmp))
            if matches!(icmp.icmp_type(), etherparse::Icmpv6Type::EchoReply(_))
    ));
}

#[tokio::test]
async fn fragmented_ipv6_icmp_echo_after_padding_hop_by_hop_reassembles() {
    let [first, second] = build_ipv6_icmp_echo_fragments_with_padding_hop_by_hop();
    let (stack, _tcp, _udp) = NetStack::new();
    let (mut sink, mut output) = stack.split();
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();

    let reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect("fragmented ICMPv6 Echo Reply behind Hop-by-Hop timed out")
            .expect("stack output closed")
            .expect("stack error");
    let packet = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
    let Some(etherparse::TransportSlice::Icmpv6(icmp)) = packet.transport else {
        panic!("expected an ICMPv6 response");
    };
    assert!(matches!(
        icmp.icmp_type(),
        etherparse::Icmpv6Type::EchoReply(echo)
            if echo.id == 7 && echo.seq == 10
    ));
    assert_eq!(icmp.payload(), b"fragmented-icmpv6-hbh");
}

#[tokio::test]
async fn fragmented_ipv6_icmp_echo_with_padding_destination_options_reassembles() {
    let [first, second] =
        build_ipv6_icmp_echo_fragments_with_padding_destination_options();
    let (stack, _tcp, _udp) = NetStack::new();
    let (mut sink, mut output) = stack.split();
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();

    let reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect(
                "fragmented ICMPv6 Echo Reply behind Destination Options timed out",
            )
            .expect("stack output closed")
            .expect("stack error");
    let packet = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
    let Some(etherparse::TransportSlice::Icmpv6(icmp)) = packet.transport else {
        panic!("expected an ICMPv6 response");
    };
    assert!(matches!(
        icmp.icmp_type(),
        etherparse::Icmpv6Type::EchoReply(echo)
            if echo.id == 7 && echo.seq == 11
    ));
    assert_eq!(icmp.payload(), b"fragmented-icmpv6-dst");
    let source = &reply.data()[8..24];
    let destination = &reply.data()[24..40];
    let message = &reply.data()[40..];
    let pseudo_header = [
        source,
        destination,
        &(message.len() as u32).to_be_bytes(),
        &[0, 0, 0, etherparse::ip_number::IPV6_ICMP.0],
        message,
    ]
    .concat();
    assert_eq!(internet_checksum(&pseudo_header), 0);
}

#[tokio::test]
async fn fragmented_ipv6_unknown_destination_option_actions_are_xray_tun_only() {
    for option in [0x1e, 0x5e, 0x9e, 0xde] {
        let [first, second] =
            build_ipv6_icmp_echo_fragments_with_unknown_destination_option(option);
        let (stack, _tcp, _udp) = NetStack::new();
        let (mut sink, mut output) = stack.split();
        sink.send(Packet::new(second.clone())).await.unwrap();
        sink.send(Packet::new(first.clone())).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                output.next()
            )
            .await
            .is_err(),
            "default strict stack should reject unknown option {option:#04x}"
        );

        let (stack, _tcp, _udp) = NetStack::new_with_mtu_xray_tun_compat(1500)
            .expect("Xray-compatible stack should be constructed");
        let (mut sink, mut output) = stack.split();
        sink.send(Packet::new(second)).await.unwrap();
        sink.send(Packet::new(first)).await.unwrap();

        if option == 0x5e {
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    output.next()
                )
                .await
                .is_err(),
                "discard-only option must not generate a response"
            );
            continue;
        }

        let reply = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            output.next(),
        )
        .await
        .expect("Xray unknown-option response timed out")
        .expect("stack output closed")
        .expect("stack returned an error");
        let packet = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
        let Some(etherparse::TransportSlice::Icmpv6(icmp)) = packet.transport else {
            panic!("expected an ICMPv6 response for option {option:#04x}");
        };
        if option == 0x1e {
            assert!(matches!(
                icmp.icmp_type(),
                etherparse::Icmpv6Type::EchoReply(echo)
                    if echo.id == 7 && echo.seq == 12
            ));
            assert_eq!(icmp.payload(), b"fragmented-icmpv6-unknown");
        } else {
            let etherparse::Icmpv6Type::ParameterProblem(error) = icmp.icmp_type()
            else {
                panic!("expected Parameter Problem for option {option:#04x}");
            };
            assert_eq!(
                error.code,
                etherparse::icmpv6::ParameterProblemCode::UnrecognizedIpv6Option
            );
            assert_eq!(error.pointer, 42);
            assert!(
                icmp.payload()
                    .windows(4)
                    .any(|part| part == [option, 2, 0x4a, 0x62]),
                "ICMP error should quote the offending Destination Option"
            );
        }
        let pseudo_header = [
            &reply.data()[8..24],
            &reply.data()[24..40],
            &(reply.data().len() as u32 - 40).to_be_bytes(),
            &[0, 0, 0, etherparse::ip_number::IPV6_ICMP.0],
            &reply.data()[40..],
        ]
        .concat();
        assert_eq!(internet_checksum(&pseudo_header), 0);
    }
}

#[tokio::test]
async fn fragmented_ipv6_destination_option_length_boundaries_match_xray() {
    let cases: [(u8, u8, [u8; 4], bool); 3] = [
        (0x1e, 5, [0x4a, 0x62, 0, 0], false), // unknown option overrun
        (1, 5, [0, 0, 0, 0], false),          // PadN overrun
        (0x1e, 0, [0, 0, 0, 0], true),        // legal zero-length unknown
    ];
    for (option, length, data, should_echo) in cases {
        let [first, second] =
            build_ipv6_icmp_echo_fragments_with_destination_option_length(
                option, length, data,
            );
        let (stack, _tcp, _udp) = NetStack::new();
        let (mut sink, mut output) = stack.split();
        sink.send(Packet::new(second.clone())).await.unwrap();
        sink.send(Packet::new(first.clone())).await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                output.next()
            )
            .await
            .is_err(),
            "strict stack must reject option {option:#04x} length {length}"
        );

        let (stack, _tcp, _udp) = NetStack::new_with_mtu_xray_tun_compat(1500)
            .expect("Xray-compatible stack should be constructed");
        let (mut sink, mut output) = stack.split();
        sink.send(Packet::new(second)).await.unwrap();
        sink.send(Packet::new(first)).await.unwrap();
        if !should_echo {
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    output.next()
                )
                .await
                .is_err(),
                "malformed option {option:#04x} length {length} must be dropped"
            );
        }
        // A malformed, completed fragment set must not poison subsequent
        // valid packets, including reuse of the same IPv6 fragment ID.
        let assert_echo = |packet: &Packet| {
            let sliced = etherparse::SlicedPacket::from_ip(packet.data()).unwrap();
            let Some(etherparse::TransportSlice::Icmpv6(icmp)) = sliced.transport
            else {
                panic!("expected ICMPv6 reply");
            };
            assert!(matches!(
                icmp.icmp_type(),
                etherparse::Icmpv6Type::EchoReply(echo)
                    if echo.id == 7 && echo.seq == 12
            ));
            assert_eq!(icmp.payload(), b"fragmented-icmpv6-unknown");
            let pseudo = [
                &packet.data()[8..24],
                &packet.data()[24..40],
                &(packet.data().len() as u32 - 40).to_be_bytes(),
                &[0, 0, 0, etherparse::ip_number::IPV6_ICMP.0],
                &packet.data()[40..],
            ]
            .concat();
            assert_eq!(internet_checksum(&pseudo), 0);
        };
        if should_echo {
            let reply = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                output.next(),
            )
            .await
            .expect("zero-length unknown option Echo Reply timed out")
            .expect("stack output closed")
            .expect("stack error");
            assert_echo(&reply);
        } else {
            let [valid_first, valid_second] =
                build_ipv6_icmp_echo_fragments_with_unknown_destination_option(0x1e);
            sink.send(Packet::new(valid_second)).await.unwrap();
            sink.send(Packet::new(valid_first)).await.unwrap();
            let reply = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                output.next(),
            )
            .await
            .expect("valid same-ID recovery Echo Reply timed out")
            .expect("stack output closed")
            .expect("stack error");
            assert_echo(&reply);
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_destination_hdr_ext_len_mismatch_is_dropped() {
    let source = [0x20; 16];
    let destination = [0x21; 16];

    for (declared_length, extra_padding, short_echo, valid_unknown) in [
        (1u8, true, false, true), // valid 16-byte header with unknown action-10 option
        (3u8, false, true, false),
        (1u8, false, false, false),
        (0u8, true, false, false),
    ] {
        let mut full = Vec::new();
        let echo_payload: &[u8] = if short_echo {
            b"x"
        } else {
            b"hdr-ext-len-check"
        };
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .icmpv6_echo_request(7, 13)
            .write(&mut full, echo_payload)
            .unwrap();

        let options = [
            etherparse::ip_number::IPV6_ICMP.0,
            declared_length,
            1,
            4,
            0,
            0,
            0,
            0,
        ];
        let mut fragmentable = options.to_vec();
        if valid_unknown {
            fragmentable.extend_from_slice(&[0x9e, 2, 0x4a, 0x62, 0, 0, 0, 0]);
        } else if extra_padding {
            fragmentable.extend_from_slice(&[0; 8]);
        }
        fragmentable.extend_from_slice(&full[40..]);

        // A valid 16-byte extension must leave the complete ICMPv6 header
        // in fragment zero; the mismatch cases deliberately do not.
        let split = if valid_unknown { 24 } else { 16 };
        let build = |part: &[u8], offset: usize, more: bool| {
            let ipv6 = etherparse::Ipv6Header {
                payload_length: (etherparse::Ipv6FragmentHeader::LEN + part.len())
                    as u16,
                next_header: etherparse::ip_number::IPV6_FRAG,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            };
            let fragment = etherparse::Ipv6FragmentHeader::new(
                etherparse::ip_number::IPV6_DEST_OPTIONS,
                etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                more,
                0x6677_889d,
            );
            [
                ipv6.to_bytes().as_slice(),
                fragment.to_bytes().as_slice(),
                part,
            ]
            .concat()
        };
        let first = build(&fragmentable[..split], 0, true);
        let second = build(&fragmentable[split..], split, false);
        for xray_mode in [false, true] {
            let (stack, _tcp, _udp) = if xray_mode {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut sink, mut output) = stack.split();
            sink.send(Packet::new(second.clone())).await.unwrap();
            sink.send(Packet::new(first.clone())).await.unwrap();
            if valid_unknown && xray_mode {
                let error_reply = tokio::time::timeout(
                    std::time::Duration::from_millis(300),
                    output.next(),
                )
                .await
                .expect(
                    "valid unknown action-10 option must produce Parameter Problem",
                )
                .expect("netstack output closed")
                .expect("netstack output error");
                let sliced =
                    etherparse::SlicedPacket::from_ip(error_reply.data()).unwrap();
                let Some(etherparse::TransportSlice::Icmpv6(icmp)) =
                    sliced.transport
                else {
                    panic!("expected ICMPv6 Parameter Problem");
                };
                let etherparse::Icmpv6Type::ParameterProblem(error) =
                    icmp.icmp_type()
                else {
                    panic!("expected Parameter Problem for a valid unknown option");
                };
                assert_eq!(
                    error.code,
                    etherparse::icmpv6::ParameterProblemCode::UnrecognizedIpv6Option
                );
                assert_eq!(error.pointer, 48);
                assert!(
                    icmp.payload()
                        .windows(4)
                        .any(|bytes| { bytes == [0x9e, 2, 0x4a, 0x62] }),
                    "Parameter Problem must quote the offending option"
                );
                let bytes = error_reply.data();
                let checksum_payload = [
                    &bytes[8..24],
                    &bytes[24..40],
                    &(bytes.len() as u32 - 40).to_be_bytes(),
                    &[0, 0, 0, etherparse::ip_number::IPV6_ICMP.0],
                    &bytes[40..],
                ]
                .concat();
                assert_eq!(internet_checksum(&checksum_payload), 0);
            } else {
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(120),
                        output.next()
                    )
                    .await
                    .is_err(),
                    "Hdr Ext Len {declared_length}, extra_padding={extra_padding}, Xray={xray_mode} must drop without ICMP error"
                );
            }

            // Check recovery on the same fragmented tuple and identification.
            let [mut valid_first, mut valid_second] =
                build_ipv6_icmp_echo_fragments_with_padding_destination_options();
            valid_first[44..48].copy_from_slice(&0x6677_889d_u32.to_be_bytes());
            valid_second[44..48].copy_from_slice(&0x6677_889d_u32.to_be_bytes());
            sink.send(Packet::new(valid_second)).await.unwrap();
            sink.send(Packet::new(valid_first)).await.unwrap();
            let reply = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                output.next(),
            )
            .await
            .expect("valid fragments should recover after malformed Hdr Ext Len")
            .expect("stack output closed")
            .expect("stack error");
            let sliced = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
            assert!(matches!(
                sliced.transport,
                Some(etherparse::TransportSlice::Icmpv6(icmp))
                    if matches!(icmp.icmp_type(), etherparse::Icmpv6Type::EchoReply(_))
            ));
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_two_destination_options_require_complete_first_fragment() {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut echo = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .icmpv6_echo_request(7, 19)
        .write(&mut echo, b"chained-options-echo")
        .unwrap();
    let build = |split: usize, semantic_second: bool| {
        let first_options = [
            etherparse::ip_number::IPV6_DEST_OPTIONS.0,
            0,
            1,
            4,
            0,
            0,
            0,
            0,
        ];
        let second_options = if semantic_second {
            [
                etherparse::ip_number::IPV6_ICMP.0,
                0,
                0x9e,
                2,
                0x4a,
                0x62,
                0,
                0,
            ]
        } else {
            [etherparse::ip_number::IPV6_ICMP.0, 0, 1, 4, 0, 0, 0, 0]
        };
        let fragmentable = [
            first_options.as_slice(),
            second_options.as_slice(),
            &echo[40..],
        ]
        .concat();
        let part = |payload: &[u8], offset: usize, more| {
            let ipv6 = etherparse::Ipv6Header {
                payload_length: (etherparse::Ipv6FragmentHeader::LEN + payload.len())
                    as u16,
                next_header: etherparse::ip_number::IPV6_FRAG,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            };
            let fragment = etherparse::Ipv6FragmentHeader::new(
                etherparse::ip_number::IPV6_DEST_OPTIONS,
                etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                more,
                0x6677_88ac,
            );
            [
                ipv6.to_bytes().as_slice(),
                fragment.to_bytes().as_slice(),
                payload,
            ]
            .concat()
        };
        [
            part(&fragmentable[..split], 0, true),
            part(&fragmentable[split..], split, false),
        ]
    };

    let (stack, _tcp, _udp) = NetStack::new_with_mtu_xray_tun_compat(1500).unwrap();
    let (mut sink, mut output) = stack.split();

    let [first, second] = build(16, false);
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), output.next())
            .await
            .is_err(),
        "Xray mode must drop an incomplete two-Destination-Options header chain"
    );

    // The same fragment ID must recover after the invalid chain, and a
    // complete first fragment (two options headers plus ICMP header) replies.
    let [first, second] = build(24, false);
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();
    let reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect("valid chained IPv6 Echo reply timed out")
            .expect("stack output closed")
            .expect("stack output error");
    let parsed = etherparse::SlicedPacket::from_ip(reply.data()).unwrap();
    let Some(etherparse::TransportSlice::Icmpv6(icmp)) = parsed.transport else {
        panic!("expected ICMPv6 Echo Reply");
    };
    assert!(matches!(
        icmp.icmp_type(),
        etherparse::Icmpv6Type::EchoReply(echo) if echo.id == 7 && echo.seq == 19
    ));
    assert_eq!(icmp.payload(), b"chained-options-echo");
    let bytes = reply.data();
    let pseudo = [
        &bytes[8..24],
        &bytes[24..40],
        &(bytes.len() as u32 - 40).to_be_bytes(),
        &[0, 0, 0, etherparse::ip_number::IPV6_ICMP.0],
        &bytes[40..],
    ]
    .concat();
    assert_eq!(internet_checksum(&pseudo), 0);

    let [first, second] = build(24, true);
    sink.send(Packet::new(second)).await.unwrap();
    sink.send(Packet::new(first)).await.unwrap();
    let error_reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect("unknown second-option error timed out")
            .expect("stack output closed")
            .expect("stack output error");
    let parsed = etherparse::SlicedPacket::from_ip(error_reply.data()).unwrap();
    let Some(etherparse::TransportSlice::Icmpv6(icmp)) = parsed.transport else {
        panic!("expected ICMPv6 Parameter Problem");
    };
    let etherparse::Icmpv6Type::ParameterProblem(error) = icmp.icmp_type() else {
        panic!("expected Parameter Problem for unknown second option");
    };
    assert_eq!(
        error.code,
        etherparse::icmpv6::ParameterProblemCode::UnrecognizedIpv6Option
    );
    assert_eq!(error.pointer, 50);
    assert!(
        icmp.payload()
            .windows(4)
            .any(|part| part == [0x9e, 2, 0x4a, 0x62]),
        "Parameter Problem must quote the second Destination Options header"
    );
    let bytes = error_reply.data();
    let pseudo = [
        &bytes[8..24],
        &bytes[24..40],
        &(bytes.len() as u32 - 40).to_be_bytes(),
        &[0, 0, 0, etherparse::ip_number::IPV6_ICMP.0],
        &bytes[40..],
    ]
    .concat();
    assert_eq!(internet_checksum(&pseudo), 0);
}

#[tokio::test]
async fn fragmented_ipv4_udp_reassembles_out_of_order() {
    let payload = b"fragmented-ipv4-udp-payload";
    let [first, second] = build_ipv4_udp_fragments(payload);
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    stack_sink.send(Packet::new(second)).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), udp_read.recv(),)
            .await
            .is_err(),
        "incomplete IPv4 fragments produced a UDP datagram"
    );

    stack_sink.send(Packet::new(first)).await.unwrap();
    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("reassembled IPv4 UDP datagram timed out")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.data(), payload);
}

#[tokio::test]
async fn ipv6_atomic_fragment_udp_is_processed_as_unfragmented() {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let payload = b"atomic-fragment";
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();
    let udp = &full[40..];
    let header = etherparse::Ipv6Header {
        payload_length: (etherparse::Ipv6FragmentHeader::LEN + udp.len()) as u16,
        next_header: etherparse::ip_number::IPV6_FRAG,
        hop_limit: 64,
        source,
        destination,
        ..Default::default()
    };
    let fragment = etherparse::Ipv6FragmentHeader::new(
        etherparse::ip_number::UDP,
        etherparse::IpFragOffset::ZERO,
        false,
        0x1234_5678,
    );
    let packet = [
        header.to_bytes().as_slice(),
        fragment.to_bytes().as_slice(),
        udp,
    ]
    .concat();

    let (stack, _tcp, udp_socket) = NetStack::new();
    let (mut sink, _) = stack.split();
    let (mut reader, _) = udp_socket.split();
    sink.send(Packet::new(packet)).await.unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), reader.recv())
            .await
            .expect("IPv6 atomic fragment UDP timed out")
            .expect("UDP stream closed");
    assert_eq!(packet.data(), payload);
}

#[tokio::test]
async fn fragmented_ipv6_udp_reassembles_out_of_order() {
    let payload = b"fragmented-ipv6-udp-payload";
    let [first, second] = build_ipv6_udp_fragments(payload);
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    stack_sink.send(Packet::new(second)).await.unwrap();
    stack_sink.send(Packet::new(first)).await.unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("reassembled IPv6 UDP datagram timed out")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.data(), payload);
}

#[tokio::test]
async fn fragment_overlap_policy_is_version_appropriate() {
    let payload = b"duplicate-fragment";
    {
        let [first, second] = build_ipv6_udp_fragments(payload);
        let (stack, _tcp, udp) = NetStack::new();
        let (mut sink, _) = stack.split();
        let (mut reader, _) = udp.split();
        for packet in [first.clone(), first, second] {
            sink.send(Packet::new(packet)).await.unwrap();
        }
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                reader.recv()
            )
            .await
            .is_err(),
            "overlapping IPv6 fragments must discard the datagram"
        );
    }
    {
        let [first, second] = build_ipv4_udp_fragments(payload);
        let (stack, _tcp, udp) = NetStack::new();
        let (mut sink, _) = stack.split();
        let (mut reader, _) = udp.split();
        for packet in [first.clone(), first, second] {
            sink.send(Packet::new(packet)).await.unwrap();
        }
        let packet = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            reader.recv(),
        )
        .await
        .expect("identical IPv4 duplicate blocked reassembly")
        .expect("UDP stream closed");
        assert_eq!(packet.data(), payload);
    }
}

#[tokio::test]
async fn fragmented_ipv6_udp_after_destination_options_reassembles() {
    let src = [0x20; 16];
    let dst = [0x21; 16];
    let payload = b"post-fragment-options";
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(src, dst, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();
    let mut data = vec![etherparse::ip_number::UDP.0, 0, 0, 0, 0, 0, 0, 0];
    data.extend_from_slice(&full[40..]);
    let build = |part: &[u8], offset: usize, more: bool| {
        let ip = etherparse::Ipv6Header {
            payload_length: (8 + part.len()) as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..Default::default()
        };
        let frag = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::IPV6_DEST_OPTIONS,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more,
            0x99aa_bbcc,
        );
        [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), part].concat()
    };
    let (stack, _tcp, udp) = NetStack::new();
    let (mut sink, _) = stack.split();
    let (mut reader, _) = udp.split();
    for packet in [build(&data[16..], 16, false), build(&data[..16], 0, true)] {
        sink.send(Packet::new(packet)).await.unwrap();
    }
    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), reader.recv())
            .await
            .expect("reassembly timed out")
            .expect("UDP stream closed");
    assert_eq!(packet.data(), payload);
}

#[tokio::test]
async fn fragmented_ipv6_udp_destination_options_first_fragment_header_is_xray_only()
{
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let payload = b"ipv6-fragment-udp-options";
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();

    let fragments = |chained: bool, split: usize| {
        let first_options = [
            if chained {
                etherparse::ip_number::IPV6_DEST_OPTIONS.0
            } else {
                etherparse::ip_number::UDP.0
            },
            0,
            1,
            4,
            0,
            0,
            0,
            0,
        ];
        let mut fragmentable = first_options.to_vec();
        if chained {
            fragmentable.extend_from_slice(&[
                etherparse::ip_number::UDP.0,
                0,
                1,
                4,
                0,
                0,
                0,
                0,
            ]);
        }
        fragmentable.extend_from_slice(&full[40..]);
        let build = |part: &[u8], offset: usize, more: bool| {
            let header = etherparse::Ipv6Header {
                payload_length: (8 + part.len()) as u16,
                next_header: etherparse::ip_number::IPV6_FRAG,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            };
            let fragment = etherparse::Ipv6FragmentHeader::new(
                etherparse::ip_number::IPV6_DEST_OPTIONS,
                etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                more,
                0x99aa_bbce,
            );
            [
                header.to_bytes().as_slice(),
                fragment.to_bytes().as_slice(),
                part,
            ]
            .concat()
        };
        [
            build(&fragmentable[..split], 0, true),
            build(&fragmentable[split..], split, false),
        ]
    };

    for xray_mode in [false, true] {
        for chained in [false, true] {
            let incomplete_split = if chained { 16 } else { 8 };
            let complete_split = incomplete_split + 8;
            let (stack, _tcp, udp) = if xray_mode {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut sink, _) = stack.split();
            let (mut reader, _) = udp.split();

            let [first, second] = fragments(chained, incomplete_split);
            sink.send(Packet::new(second)).await.unwrap();
            sink.send(Packet::new(first)).await.unwrap();
            if xray_mode {
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        reader.recv()
                    )
                    .await
                    .is_err(),
                    "Xray UDP must drop incomplete first-fragment header chain (chained={chained})"
                );
            } else {
                let packet = tokio::time::timeout(
                    std::time::Duration::from_millis(300),
                    reader.recv(),
                )
                .await
                .expect("ordinary netstack should retain prior reassembly behavior")
                .expect("UDP receiver closed");
                assert_eq!(packet.data(), payload);
            }

            // Reuse the same IPv6 fragment ID to show the invalid first
            // fragment did not poison subsequent reassembly or UDP dispatch.
            let [first, second] = fragments(chained, complete_split);
            sink.send(Packet::new(second)).await.unwrap();
            sink.send(Packet::new(first)).await.unwrap();
            let packet = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                reader.recv(),
            )
            .await
            .expect("complete first-fragment UDP header must dispatch")
            .expect("UDP receiver closed");
            assert_eq!(packet.data(), payload);
            assert_eq!(packet.local_addr.port(), 5000);
            assert_eq!(packet.remote_addr.port(), 5001);
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_udp_with_padding_hop_by_hop_reassembles() {
    let src = [0x20; 16];
    let dst = [0x21; 16];
    let payload = b"pre-fragment-padding";
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(src, dst, 64)
        .udp(5000, 5001)
        .write(&mut full, payload)
        .unwrap();
    let udp = &full[40..];
    let build = |part: &[u8], offset: usize, more: bool| {
        let ip = etherparse::Ipv6Header {
            payload_length: (16 + part.len()) as u16,
            next_header: etherparse::ip_number::IPV6_HOP_BY_HOP,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..Default::default()
        };
        let hop_by_hop = [etherparse::ip_number::IPV6_FRAG.0, 0, 0, 0, 0, 0, 0, 0];
        let frag = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::UDP,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more,
            0x3344_5566,
        );
        [
            ip.to_bytes().as_slice(),
            hop_by_hop.as_slice(),
            frag.to_bytes().as_slice(),
            part,
        ]
        .concat()
    };
    let (stack, _tcp, udp_socket) = NetStack::new();
    let (mut sink, _) = stack.split();
    let (mut reader, _) = udp_socket.split();
    for packet in [build(&udp[16..], 16, false), build(&udp[..16], 0, true)] {
        sink.send(Packet::new(packet)).await.unwrap();
    }
    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), reader.recv())
            .await
            .expect("padding-only Hop-by-Hop reassembly timed out")
            .expect("UDP stream closed");
    assert_eq!(packet.data(), payload);
}

#[tokio::test]
async fn fragmented_ipv6_udp_with_semantic_destination_option_is_rejected() {
    let src = [0x20; 16];
    let dst = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(src, dst, 64)
        .udp(5000, 5001)
        .write(&mut full, b"semantic-option")
        .unwrap();
    let mut data = vec![etherparse::ip_number::UDP.0, 0, 0x22, 0, 0, 0, 0, 0];
    data.extend_from_slice(&full[40..]);
    let build = |part: &[u8], offset: usize, more: bool| {
        let ip = etherparse::Ipv6Header {
            payload_length: (8 + part.len()) as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..Default::default()
        };
        let frag = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::IPV6_DEST_OPTIONS,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more,
            0x4455_6677,
        );
        [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), part].concat()
    };
    let (stack, _tcp, udp) = NetStack::new();
    let (mut sink, _) = stack.split();
    let (mut reader, _) = udp.split();
    for packet in [build(&data[16..], 16, false), build(&data[..16], 0, true)] {
        sink.send(Packet::new(packet)).await.unwrap();
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), reader.recv())
            .await
            .is_err(),
        "semantic Destination Option was silently stripped"
    );
}

#[tokio::test]
async fn fragmented_ipv6_udp_with_auth_after_fragment_is_rejected() {
    let src = [0x20; 16];
    let dst = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(src, dst, 64)
        .udp(5000, 5001)
        .write(&mut full, b"auth-must-not-bypass")
        .unwrap();
    let mut data = vec![
        etherparse::ip_number::UDP.0,
        1,
        0,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        1,
    ];
    data.extend_from_slice(&full[40..]);
    let build = |part: &[u8], offset: usize, more: bool| {
        let ip = etherparse::Ipv6Header {
            payload_length: (8 + part.len()) as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..Default::default()
        };
        let frag = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::AUTH,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more,
            0x5566_7788,
        );
        [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), part].concat()
    };
    let (stack, _tcp, udp) = NetStack::new();
    let (mut sink, _) = stack.split();
    let (mut reader, _) = udp.split();
    for packet in [build(&data[16..], 16, false), build(&data[..16], 0, true)] {
        sink.send(Packet::new(packet)).await.unwrap();
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), reader.recv())
            .await
            .is_err(),
        "fragmented AH header was silently bypassed"
    );
}

#[tokio::test]
async fn fragmented_ipv6_tcp_destination_options_requires_eight_bytes_in_first_fragment_for_xray()
 {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(source, destination, 64)
        .tcp(1234, 80, 0, 65535)
        .syn()
        .write(&mut full, b"tcp-first-header")
        .unwrap();

    let fragments = |chained: bool, include_eight_tcp_bytes: bool| {
        let mut data = vec![
            if chained {
                etherparse::ip_number::IPV6_DEST_OPTIONS.0
            } else {
                etherparse::ip_number::TCP.0
            },
            0,
            1,
            4,
            0,
            0,
            0,
            0,
        ];
        if chained {
            data.extend_from_slice(&[
                etherparse::ip_number::TCP.0,
                0,
                1,
                4,
                0,
                0,
                0,
                0,
            ]);
        }
        let split = data.len() + if include_eight_tcp_bytes { 8 } else { 0 };
        data.extend_from_slice(&full[40..]);
        let part = |body: &[u8], offset: usize, more: bool| {
            let ipv6 = etherparse::Ipv6Header {
                payload_length: (8 + body.len()) as u16,
                next_header: etherparse::ip_number::IPV6_FRAG,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            };
            let fragment = etherparse::Ipv6FragmentHeader::new(
                etherparse::ip_number::IPV6_DEST_OPTIONS,
                etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                more,
                0x7788_99ab,
            );
            [
                ipv6.to_bytes().as_slice(),
                fragment.to_bytes().as_slice(),
                body,
            ]
            .concat()
        };
        [
            part(&data[..split], 0, true),
            part(&data[split..], split, false),
        ]
    };

    for chained in [false, true] {
        for xray_mode in [false, true] {
            let (stack, _tcp, _udp) = if xray_mode {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut sink, mut output) = stack.split();

            let [first, second] = fragments(chained, false);
            sink.send(Packet::new(second)).await.unwrap();
            sink.send(Packet::new(first)).await.unwrap();
            if xray_mode {
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        output.next()
                    )
                    .await
                    .is_err(),
                    "Xray TUN must drop fragment zero with no TCP bytes (chained={chained})"
                );
                // Same fragment ID must recover after invalid first fragment.
                let [first, second] = fragments(chained, true);
                sink.send(Packet::new(second)).await.unwrap();
                sink.send(Packet::new(first)).await.unwrap();
            }
            let reply = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                output.next(),
            )
            .await
            .expect("first-fragment TCP SYN-ACK timed out")
            .expect("stack output closed")
            .expect("stack error");
            assert!(
                is_any_ip_syn_ack(reply.data()),
                "eight TCP bytes suffice in Xray mode; default mode retains acceptance"
            );
        }
    }
}

#[tokio::test]
async fn tcp_blackhole_like_stream_close_obeys_xray_timewait_opt_in() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    // Isolate the local smoltcp TCP lifetime from routing/dispatcher logic.
    // Compare immediate stream Drop (outbound selection failure) with
    // AsyncWrite::shutdown followed by Drop (the dispatcher error branch).
    let source = [0x51; 16];
    let destination = [0x52; 16];
    for xray_compat in [false, true] {
        for explicit_shutdown in [false, true] {
            let (stack, mut listener, _udp) = if xray_compat {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut input, mut output) = stack.split();
            let client_port = 46220;
            let client_isn = 0x6430_0000u32;
            let build = |seq: u32, ack: Option<u32>, syn: bool, fin: bool| {
                let mut header =
                    etherparse::TcpHeader::new(client_port, 39647, seq, 4096);
                header.syn = syn;
                header.fin = fin;
                if let Some(ack) = ack {
                    header.ack = true;
                    header.acknowledgment_number = ack;
                }
                let mut packet = Vec::new();
                etherparse::PacketBuilder::ipv6(source, destination, 64)
                    .tcp_header(header)
                    .write(&mut packet, &[])
                    .unwrap();
                Packet::new(packet)
            };
            let receive = |packet: &Packet| {
                let sliced =
                    etherparse::SlicedPacket::from_ip(packet.data()).unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport
                else {
                    panic!("expected TCP");
                };
                (
                    tcp.sequence_number(),
                    tcp.acknowledgment_number(),
                    tcp.syn(),
                    tcp.fin(),
                    tcp.ack(),
                    tcp.rst(),
                )
            };
            input
                .send(build(client_isn, None, true, false))
                .await
                .unwrap();
            let syn_ack =
                tokio::time::timeout(Duration::from_millis(800), output.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            let (isn, ack, syn, _, ack_bit, rst) = receive(&syn_ack);
            assert!(syn && ack_bit && !rst);
            assert_eq!(ack, client_isn + 1);
            let server_seq = isn.wrapping_add(1);
            let mut stream =
                tokio::time::timeout(Duration::from_millis(800), listener.next())
                    .await
                    .unwrap()
                    .unwrap();
            input
                .send(build(client_isn + 1, Some(server_seq), false, false))
                .await
                .unwrap();
            if explicit_shutdown {
                stream.shutdown().await.unwrap();
            }
            drop(stream);

            let fin_seq = tokio::time::timeout(Duration::from_millis(1000), async {
                loop {
                    let frame = output.next().await.unwrap().unwrap();
                    let (seq, _, _, fin, _, rst) = receive(&frame);
                    assert!(!rst, "early close emitted RST");
                    if fin {
                        return seq;
                    }
                }
            })
            .await
            .expect("blackhole-like close must deliver FIN");
            assert_eq!(fin_seq, server_seq);
            let closed_seq = server_seq.wrapping_add(1);
            input
                .send(build(client_isn + 1, Some(closed_seq), false, false))
                .await
                .unwrap();
            input
                .send(build(client_isn + 1, Some(closed_seq), false, true))
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_millis(900), async {
                loop {
                    let frame = output.next().await.unwrap().unwrap();
                    let (_, ack, _, _, ack_bit, rst) = receive(&frame);
                    assert!(!rst, "close handshake emitted RST");
                    if ack_bit && ack == client_isn + 2 {
                        break;
                    }
                }
            })
            .await
            .expect("client FIN not ACKed");

            // The Xray-opt-in listener retains smoltcp TIME-WAIT sockets
            // for retransmitted FINs; the ordinary constructor preserves
            // its original immediate tuple-reuse behavior.
            tokio::time::sleep(Duration::from_millis(20)).await;
            while let Ok(Some(Ok(_))) =
                tokio::time::timeout(Duration::from_millis(5), output.next()).await
            {
            }
            input
                .send(build(client_isn + 1, Some(closed_seq), false, true))
                .await
                .unwrap();
            let duplicate_ack =
                tokio::time::timeout(Duration::from_millis(120), async {
                    loop {
                        let frame = output.next().await.unwrap().unwrap();
                        let (_, ack, _, _, ack_bit, rst) = receive(&frame);
                        if ack_bit && ack == client_isn + 2 && !rst {
                            return true;
                        }
                    }
                })
                .await
                .unwrap_or(false);

            if xray_compat && explicit_shutdown {
                // In-window RST on a TIME-WAIT tuple must not assassinate
                // the old connection. Pinned Xray/gVisor discards it.
                let mut rst = etherparse::TcpHeader::new(
                    client_port,
                    39647,
                    client_isn + 2,
                    4096,
                );
                rst.rst = true;
                rst.ack = true;
                rst.acknowledgment_number = closed_seq;
                let mut wire = Vec::new();
                etherparse::PacketBuilder::ipv6(source, destination, 64)
                    .tcp_header(rst)
                    .write(&mut wire, &[])
                    .unwrap();
                input.send(Packet::new(wire)).await.unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            let fresh_isn = client_isn + 100_000;
            input
                .send(build(fresh_isn, None, true, false))
                .await
                .unwrap();
            let tuple_reopened =
                tokio::time::timeout(Duration::from_millis(800), async {
                    loop {
                        let frame = output.next().await.unwrap().unwrap();
                        let (_, ack, syn, _, ack_bit, _) = receive(&frame);
                        if syn && ack_bit && ack == fresh_isn + 1 {
                            return true;
                        }
                    }
                })
                .await
                .unwrap_or(false);
            assert_eq!(
                duplicate_ack, xray_compat,
                "TIME-WAIT duplicate FIN mismatch: xray_compat={xray_compat}, explicit_shutdown={explicit_shutdown}"
            );
            assert_eq!(
                tuple_reopened, !xray_compat,
                "TIME-WAIT tuple admission mismatch: xray_compat={xray_compat}, explicit_shutdown={explicit_shutdown}"
            );
            if xray_compat && explicit_shutdown {
                // smoltcp 0.13 uses a 10-second TIME-WAIT close timer.
                // Its expiration must release the old tuple for new traffic.
                tokio::time::sleep(Duration::from_secs(11)).await;
                input
                    .send(build(fresh_isn + 1000, None, true, false))
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_millis(1200), async {
                    loop {
                        let frame = output.next().await.unwrap().unwrap();
                        let (_, ack, syn, _, ack_bit, _) = receive(&frame);
                        if syn && ack_bit && ack == fresh_isn + 1001 {
                            break;
                        }
                    }
                })
                .await
                .expect("expired TIME-WAIT tuple must accept a fresh SYN");
            }
        }
    }
}

#[tokio::test]
#[ignore = "explicit 512-socket capacity test; reserves large buffers but does not fill them"]
async fn xray_tcp_512_active_socket_cap_and_rst_recovery() {
    use std::time::Duration;

    // Exercises the actual listener, not only the weak-handle capacity
    // helper. Hold 512 simultaneous SYN-RECEIVED sockets; a 513th tuple
    // must be rejected without allocating another accept-side stream.
    // A valid RST frees one slot; verify a fresh tuple is then admitted.
    const CAP: u16 = 512;
    let (stack, mut listener, _udp) =
        NetStack::new_with_mtu_xray_tun_compat(1500).unwrap();
    let (mut input, mut output) = stack.split();
    let src = [0x71; 16];
    let dst = [0x72; 16];
    let tcp = |port: u16, seq: u32, ack: Option<u32>, rst: bool| {
        let mut header = etherparse::TcpHeader::new(port, 39647, seq, 4096);
        header.syn = !rst;
        header.rst = rst;
        if !rst {
            // Populate a Timestamp recent-value entry for every accepted
            // flow, covering the weak-owner cache at the actual 512 cap.
            header
                .set_options(&[etherparse::TcpOptionElement::Timestamp(
                    u32::from(port) + 1_000,
                    0,
                )])
                .unwrap();
        }
        if let Some(ack) = ack {
            header.ack = true;
            header.acknowledgment_number = ack;
        }
        let mut raw = Vec::new();
        etherparse::PacketBuilder::ipv6(src, dst, 64)
            .tcp_header(header)
            .write(&mut raw, &[])
            .unwrap();
        Packet::new(raw)
    };
    let parse = |frame: &Packet| {
        let sliced = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
        let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport else {
            panic!("expected TCP response");
        };
        (
            tcp.destination_port(),
            tcp.sequence_number(),
            tcp.acknowledgment_number(),
            tcp.syn(),
            tcp.ack(),
            tcp.rst(),
        )
    };
    let mut streams = Vec::with_capacity(usize::from(CAP));
    let mut server_seq = Vec::with_capacity(usize::from(CAP));
    let started = std::time::Instant::now();
    for i in 0..CAP {
        let port = 50000 + i;
        let seq = 10000 + u32::from(i) * 1000;
        input.send(tcp(port, seq, None, false)).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = output.next().await.unwrap().unwrap();
                let value = parse(&frame);
                if value.0 == port && value.3 && value.4 {
                    return value;
                }
            }
        })
        .await
        .expect("socket admission stalled near capacity");
        assert!(!reply.5);
        assert_eq!(reply.2, seq + 1);
        server_seq.push(reply.1.wrapping_add(1));
        streams.push(
            tokio::time::timeout(Duration::from_secs(2), listener.next())
                .await
                .expect("no stream for allowed SYN")
                .expect("listener closed"),
        );
    }
    eprintln!(
        "Xray TCP cap test: {} accepted sockets, duration={:?}",
        streams.len(),
        started.elapsed()
    );
    // Optional Linux-only process observation. This is not an assertion
    // about production memory use; exact RSS depends on allocator/build.
    #[cfg(target_os = "linux")]
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmRSS:")
                || line.starts_with("VmHWM:")
                || line.starts_with("VmSize:")
            {
                eprintln!("Xray TCP cap test: {line}");
            }
        }
    }
    // Exercise the configured 512-handle limit while all streams remain
    // owned. The new SYN must not get SYN-ACK nor deliver a new stream.
    let excess_port = 50000 + CAP;
    input
        .send(tcp(excess_port, 800000, None, false))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(400), async {
            loop {
                let frame = output.next().await.unwrap().unwrap();
                let reply = parse(&frame);
                if reply.0 == excess_port && reply.3 && reply.4 {
                    break;
                }
            }
        })
        .await
        .is_err(),
        "513th tuple unexpectedly admitted"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.next())
            .await
            .is_err(),
        "513th stream unexpectedly delivered"
    );

    // Remove the first flow with an established-state, checksum-valid RST.
    // This is deliberately *not* TIME-WAIT RST, which must be ignored.
    input
        .send(tcp(50000, 10000 + 1, Some(server_seq[0]), true))
        .await
        .unwrap();
    drop(streams.remove(0));
    tokio::time::sleep(Duration::from_millis(50)).await;
    let new_port = excess_port + 1;
    input
        .send(tcp(new_port, 900000, None, false))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let reply = parse(&frame);
            if reply.0 == new_port && reply.3 && reply.4 {
                assert_eq!(reply.2, 900001);
                break;
            }
        }
    })
    .await
    .expect("TCP slot not recovered after established RST");
    drop(streams);
    tokio::time::timeout(Duration::from_secs(3), listener.shutdown())
        .await
        .expect("TCP listener shutdown stalled with near-cap sockets")
        .expect("TCP listener shutdown failed");
}

#[tokio::test]
async fn xray_timewait_burst_preserves_new_admission_and_recovers_on_expiry() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    // Bounded local churn: retain 32 independently closed sockets in Xray
    // TIME-WAIT, continue to admit unrelated tuples and reclaim the oldest
    // after smoltcp's 10-second timer. This is not a 512-flow load benchmark.
    let (stack, mut listener, _udp) =
        NetStack::new_with_mtu_xray_tun_compat(1500).unwrap();
    let (mut input, mut output) = stack.split();
    let src = [0x61; 16];
    let dst = [0x62; 16];
    let build = |port: u16, seq: u32, ack: Option<u32>, syn: bool, fin: bool| {
        let mut header = etherparse::TcpHeader::new(port, 39647, seq, 4096);
        header.syn = syn;
        header.fin = fin;
        if let Some(ack) = ack {
            header.ack = true;
            header.acknowledgment_number = ack;
        }
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv6(src, dst, 64)
            .tcp_header(header)
            .write(&mut packet, &[])
            .unwrap();
        Packet::new(packet)
    };
    let receive = |frame: &Packet| {
        let packet = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
        let Some(etherparse::TransportSlice::Tcp(tcp)) = packet.transport else {
            panic!("expected TCP response")
        };
        (
            tcp.destination_port(),
            tcp.sequence_number(),
            tcp.acknowledgment_number(),
            tcp.syn(),
            tcp.fin(),
            tcp.rst(),
            tcp.ack(),
        )
    };
    let initial = std::time::Instant::now();
    for number in 0..32_u16 {
        let port = 47000 + number;
        let cisn = 700_000 + u32::from(number) * 1000;
        input
            .send(build(port, cisn, None, true, false))
            .await
            .unwrap();
        let (_, server_isn, synack_ack, syn, _, rst, _) =
            tokio::time::timeout(Duration::from_millis(750), async {
                loop {
                    let frame = output.next().await.unwrap().unwrap();
                    let fields = receive(&frame);
                    if fields.0 == port && fields.3 {
                        return fields;
                    }
                }
            })
            .await
            .expect("SYN-ACK missing under bounded short-flow churn");
        assert!(syn && !rst);
        assert_eq!(synack_ack, cisn + 1);
        let server_next = server_isn.wrapping_add(1);
        let mut stream =
            tokio::time::timeout(Duration::from_millis(500), listener.next())
                .await
                .expect("accepted stream not delivered")
                .expect("TCP listener ended");
        input
            .send(build(port, cisn + 1, Some(server_next), false, false))
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
        drop(stream);
        let fin_seq = tokio::time::timeout(Duration::from_millis(750), async {
            loop {
                let frame = output.next().await.unwrap().unwrap();
                let fields = receive(&frame);
                if fields.0 == port && fields.4 {
                    assert!(!fields.5, "server close emitted RST");
                    return fields.1;
                }
            }
        })
        .await
        .expect("server FIN missing");
        assert_eq!(fin_seq, server_next);
        let closed_seq = server_next + 1;
        input
            .send(build(port, cisn + 1, Some(closed_seq), false, false))
            .await
            .unwrap();
        input
            .send(build(port, cisn + 1, Some(closed_seq), false, true))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_millis(750), async {
            loop {
                let frame = output.next().await.unwrap().unwrap();
                let fields = receive(&frame);
                if fields.0 == port && fields.6 && fields.2 == cisn + 2 {
                    assert!(!fields.5, "FIN ACK was RST");
                    break;
                }
            }
        })
        .await
        .expect("final ACK missing in churn case");
    }
    assert!(
        initial.elapsed() < Duration::from_secs(8),
        "test took too long to exercise simultaneous TIME-WAIT retention"
    );

    // Existing source tuples must not reopen while retained, even as a
    // different tuple passes admission after the burst.
    input
        .send(build(47000, 900_000, None, true, false))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(180), async {
            loop {
                let frame = output.next().await.unwrap().unwrap();
                let fields = receive(&frame);
                if fields.0 == 47000 && fields.3 && fields.6 {
                    break;
                }
            }
        })
        .await
        .is_err(),
        "retained tuple reopened before its timeout"
    );
    input
        .send(build(49000, 900_000, None, true, false))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(750), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let fields = receive(&frame);
            if fields.0 == 49000 && fields.3 && fields.6 {
                break;
            }
        }
    })
    .await
    .expect("unrelated source tuple blocked by TIME-WAIT burst");

    // Timer expiration releases every reservation without explicit traffic
    // to old flows. A post-expiry SYN must not remain permanently blocked.
    tokio::time::sleep(Duration::from_secs(11)).await;
    input
        .send(build(47000, 901_000, None, true, false))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(900), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let fields = receive(&frame);
            if fields.0 == 47000 && fields.3 && fields.6 && fields.2 == 901_001 {
                break;
            }
        }
    })
    .await
    .expect("expired TIME-WAIT reservation did not release");
    tokio::time::timeout(Duration::from_secs(2), listener.shutdown())
        .await
        .expect("listener TIME-WAIT shutdown stalled")
        .expect("listener shutdown failed");
}

#[tokio::test]
async fn active_ipv6_tcp_fin_timewait_duplicate_fin_and_same_tuple_reopen() {
    use etherparse::TcpOptionElement as Opt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let source = [0x41; 16];
    let destination = [0x42; 16];
    for xray in [false, true] {
        for (chained, client_first) in
            [(false, false), (true, false), (false, true), (true, true)]
        {
            let (stack, mut listener, _udp) = if xray {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut input, mut output) = stack.split();
            let port = if chained { 46393 } else { 46392 };
            let cisn = 1000u32;
            let make = |seq: u32,
                        ack: Option<u32>,
                        syn: bool,
                        fin: bool,
                        payload: &[u8]| {
                let mut header = etherparse::TcpHeader::new(port, 80, seq, 4096);
                header.syn = syn;
                header.fin = fin;
                if let Some(ack) = ack {
                    header.ack = true;
                    header.acknowledgment_number = ack;
                }
                let mut wire = Vec::new();
                etherparse::PacketBuilder::ipv6(source, destination, 64)
                    .tcp_header(header)
                    .write(&mut wire, payload)
                    .unwrap();
                wire
            };
            let fragment = |tcp: &[u8], ident: u32| {
                let mut options =
                    vec![etherparse::ip_number::TCP.0, 0, 1, 4, 0, 0, 0, 0];
                if chained {
                    options[0] = etherparse::ip_number::IPV6_DEST_OPTIONS.0;
                    options.extend_from_slice(&[
                        etherparse::ip_number::TCP.0,
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                    ]);
                }
                let data = [options.as_slice(), tcp].concat();
                let split = options.len() + 8;
                let part = |bytes: &[u8], offset: usize, more: bool| {
                    let ip = etherparse::Ipv6Header {
                        payload_length: (8 + bytes.len()) as u16,
                        next_header: etherparse::ip_number::IPV6_FRAG,
                        hop_limit: 64,
                        source,
                        destination,
                        ..Default::default()
                    };
                    let frag = etherparse::Ipv6FragmentHeader::new(
                        etherparse::ip_number::IPV6_DEST_OPTIONS,
                        etherparse::IpFragOffset::try_new((offset / 8) as u16)
                            .unwrap(),
                        more,
                        ident,
                    );
                    [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), bytes]
                        .concat()
                };
                [
                    part(&data[split..], split, false),
                    part(&data[..split], 0, true),
                ]
            };
            let mut syn = etherparse::TcpHeader::new(port, 80, cisn, 4096);
            syn.syn = true;
            syn.set_options(&[Opt::Timestamp(52_000, 0)]).unwrap();
            let mut syn_wire = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(syn)
                .write(&mut syn_wire, &[])
                .unwrap();
            input.send(Packet::new(syn_wire)).await.unwrap();
            let synack = tokio::time::timeout(
                std::time::Duration::from_millis(600),
                output.next(),
            )
            .await
            .expect("TIME_WAIT handshake timed out")
            .expect("netstack output ended")
            .expect("packet error");
            let server_seq = match etherparse::SlicedPacket::from_ip(synack.data())
                .unwrap()
                .transport
            {
                Some(etherparse::TransportSlice::Tcp(tcp)) => {
                    assert!(tcp.syn() && tcp.ack());
                    let negotiated_ts = tcp
                        .options_iterator()
                        .filter_map(Result::ok)
                        .any(|opt| matches!(opt, Opt::Timestamp(_, _)));
                    assert_eq!(
                        negotiated_ts, xray,
                        "only Xray TUN opts into Timestamp"
                    );
                    tcp.sequence_number().wrapping_add(1)
                }
                _ => panic!("TIME_WAIT missing SYN-ACK"),
            };
            let mut stream = tokio::time::timeout(
                std::time::Duration::from_millis(600),
                listener.next(),
            )
            .await
            .expect("TIME_WAIT listener timed out")
            .expect("listener ended");
            input
                .send(Packet::new(make(1001, Some(server_seq), false, false, &[])))
                .await
                .unwrap();
            let old_client_data = b"original-client-tcp-bytes";
            input
                .send(Packet::new(make(
                    1001,
                    Some(server_seq),
                    false,
                    false,
                    old_client_data,
                )))
                .await
                .unwrap();
            let mut originally_received = vec![0; old_client_data.len()];
            tokio::time::timeout(
                std::time::Duration::from_millis(600),
                stream.read_exact(&mut originally_received),
            )
            .await
            .expect("old connection data was not delivered")
            .expect("old connection data read failed");
            assert_eq!(originally_received, old_client_data);
            let client_fin_seq = 1001 + old_client_data.len() as u32;
            if client_first {
                // Exercise the passive server close direction independently:
                // client FIN first -> local CLOSE-WAIT. The server must
                // still be allowed to write, and later shutdown triggers
                // LAST-ACK, not the server-first FIN-WAIT/TIME-WAIT path.
                let client_fin =
                    make(client_fin_seq, Some(server_seq), false, true, &[]);
                let fragments = fragment(&client_fin[40..], 0x7766_9910);
                input.send(Packet::new(fragments[0].clone())).await.unwrap();
                input.send(Packet::new(fragments[1].clone())).await.unwrap();
                let mut eof = [0u8; 1];
                let n = tokio::time::timeout(
                    std::time::Duration::from_millis(600),
                    stream.read(&mut eof),
                )
                .await
                .expect("client-first FIN not delivered to stream")
                .expect("reading client-first FIN failed");
                assert_eq!(n, 0, "peer FIN must deliver read EOF, xray={xray}");
            }
            let marker = b"active-fin-timewait";
            tokio::time::timeout(
                std::time::Duration::from_millis(700),
                stream.write_all(marker),
            )
            .await
            .expect("server write stalled")
            .expect("server write failed");
            tokio::time::timeout(
                std::time::Duration::from_millis(700),
                stream.shutdown(),
            )
            .await
            .expect("server active FIN shutdown stalled")
            .expect("server active FIN shutdown failed");
            let mut received = Vec::new();
            let mut fin_seen = false;
            let mut peer_fin_acked = false;
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while received.len() < marker.len() || !fin_seen {
                    let frame = output
                        .next()
                        .await
                        .expect("TIME_WAIT output ended")
                        .unwrap();
                    let Some(etherparse::TransportSlice::Tcp(tcp)) =
                        etherparse::SlicedPacket::from_ip(frame.data())
                            .ok()
                            .and_then(|ip| ip.transport)
                    else {
                        continue;
                    };
                    assert!(!tcp.rst(), "server actively closing flow reset");
                    if client_first
                        && tcp.ack()
                        && tcp.acknowledgment_number() == client_fin_seq + 1
                    {
                        peer_fin_acked = true;
                    }
                    if !tcp.payload().is_empty()
                        && tcp.sequence_number()
                            == server_seq + received.len() as u32
                    {
                        received.extend_from_slice(tcp.payload());
                    }
                    if tcp.fin() {
                        assert_eq!(
                            tcp.sequence_number() + tcp.payload().len() as u32,
                            server_seq + marker.len() as u32
                        );
                        fin_seen = true;
                    }
                }
            })
            .await
            .expect("server active FIN/stream bytes missing");
            assert_eq!(received, marker);
            let closed_seq = server_seq + marker.len() as u32 + 1;
            input
                .send(Packet::new(make(
                    client_fin_seq + u32::from(client_first),
                    Some(closed_seq),
                    false,
                    false,
                    &[],
                )))
                .await
                .unwrap();
            let fin = make(client_fin_seq, Some(closed_seq), false, true, &[]);
            if !client_first {
                let first = fragment(&fin[40..], 0x7766_9900);
                input.send(Packet::new(first[0].clone())).await.unwrap();
                input.send(Packet::new(first[1].clone())).await.unwrap();
                tokio::time::timeout(std::time::Duration::from_millis(900), async {
                    loop {
                        let frame = output
                            .next()
                            .await
                            .expect("final FIN ACK output ended")
                            .unwrap();
                        let Some(etherparse::TransportSlice::Tcp(tcp)) =
                            etherparse::SlicedPacket::from_ip(frame.data())
                                .ok()
                                .and_then(|ip| ip.transport)
                        else {
                            continue;
                        };
                        assert!(!tcp.rst(), "TIME_WAIT FIN exchange reset");
                        if tcp.ack()
                            && tcp.acknowledgment_number() == client_fin_seq + 1
                        {
                            break;
                        }
                    }
                })
                .await
                .expect("server failed to ACK client's final FIN");
            } else {
                assert!(peer_fin_acked, "server did not ACK client-first FIN");
            }
            let second = fragment(&fin[40..], 0x7766_9901);
            input.send(Packet::new(second[0].clone())).await.unwrap();
            input.send(Packet::new(second[1].clone())).await.unwrap();
            // Replay *actual* previously delivered client application
            // bytes with their original sequence after server TIME_WAIT.
            // A fresh fragment ID forces reassembly to see the replay,
            // while the old connection must not deliver the bytes again.
            let stale = make(1001, Some(closed_seq), false, false, old_client_data);
            let stale_parts = fragment(&stale[40..], 0x7766_9902);
            input
                .send(Packet::new(stale_parts[0].clone()))
                .await
                .unwrap();
            input
                .send(Packet::new(stale_parts[1].clone()))
                .await
                .unwrap();
            // RFC 1122 allows a new connection incarnation if the new
            // ISN is higher than any used by the previous client flow.
            // Both constructors must not let old FIN become application
            // data, regardless of their exact TIME_WAIT ACK timer.
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            let new_isn = 100_000u32;
            input
                .send(Packet::new(make(new_isn, None, true, false, &[])))
                .await
                .unwrap();
            if xray && !client_first {
                // The server-first FIN path enters TIME-WAIT; while its
                // bounded timer runs, the old tuple must not be reopened.
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(250),
                        async {
                            loop {
                                let frame = output.next().await.unwrap().unwrap();
                                if let Some(etherparse::TransportSlice::Tcp(tcp)) =
                                    etherparse::SlicedPacket::from_ip(frame.data())
                                        .ok()
                                        .and_then(|ip| ip.transport)
                                    && tcp.syn()
                                    && tcp.ack()
                                    && tcp.acknowledgment_number() == new_isn + 1
                                {
                                    break;
                                }
                            }
                        }
                    )
                    .await
                    .is_err(),
                    "Xray TUN TIME-WAIT prematurely accepted same-tuple SYN"
                );
                continue;
            }
            let fresh_synack = tokio::time::timeout(
                std::time::Duration::from_millis(1100),
                async {
                    loop {
                        let frame = output
                            .next()
                            .await
                            .expect("reused tuple output ended")
                            .unwrap();
                        let Some(etherparse::TransportSlice::Tcp(tcp)) =
                            etherparse::SlicedPacket::from_ip(frame.data())
                                .ok()
                                .and_then(|ip| ip.transport)
                        else {
                            continue;
                        };
                        if tcp.syn()
                            && tcp.ack()
                            && tcp.acknowledgment_number() == new_isn + 1
                        {
                            return tcp.sequence_number().wrapping_add(1);
                        }
                    }
                },
            )
            .await
            .expect("same 4-tuple fresh SYN was not accepted");
            let mut fresh = tokio::time::timeout(
                std::time::Duration::from_millis(600),
                listener.next(),
            )
            .await
            .expect("fresh same-tuple accept timed out")
            .expect("listener closed");
            let new_payload = b"fresh-timewait-incarnation";
            input
                .send(Packet::new(make(
                    new_isn + 1,
                    Some(fresh_synack),
                    false,
                    false,
                    new_payload,
                )))
                .await
                .unwrap();
            let mut bytes = vec![0; new_payload.len()];
            tokio::time::timeout(
                std::time::Duration::from_millis(600),
                fresh.read_exact(&mut bytes),
            )
            .await
            .expect("reused tuple fresh data stalled")
            .expect("fresh read failed");
            assert_eq!(
                &bytes, new_payload,
                "xray={xray} chained={chained} client_first={client_first}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "explicit 512 KiB receive-backpressure + Timestamp probe (not in default CI)"]
async fn xray_tcp_actual_receive_zero_window_timestamp_probe() {
    use etherparse::TcpOptionElement as Opt;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    let (stack, mut listener, _udp) =
        NetStack::new_with_mtu_xray_tun_compat(1500).unwrap();
    let (mut input, mut output) = stack.split();
    let src = [0x69; 16];
    let dst = [0x6a; 16];
    let client_port = 46899;
    let initial_seq = 120_000u32;
    let mut syn = etherparse::TcpHeader::new(client_port, 39643, initial_seq, 4096);
    syn.syn = true;
    syn.set_options(&[Opt::WindowScale(3), Opt::Timestamp(40_000, 0)])
        .unwrap();
    let mut syn_packet = Vec::new();
    etherparse::PacketBuilder::ipv6(src, dst, 64)
        .tcp_header(syn)
        .write(&mut syn_packet, &[])
        .unwrap();
    input.send(Packet::new(syn_packet)).await.unwrap();
    let synack = tokio::time::timeout(Duration::from_secs(2), output.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let parsed = etherparse::SlicedPacket::from_ip(synack.data()).unwrap();
    let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport else {
        panic!("expected SYN-ACK");
    };
    assert!(tcp.syn() && tcp.ack());
    let server_seq = tcp.sequence_number().wrapping_add(1);
    assert!(
        tcp.options_iterator()
            .filter_map(Result::ok)
            .any(|opt| matches!(opt, Opt::Timestamp(_, 40_000)))
    );
    let mut stream = tokio::time::timeout(Duration::from_secs(1), listener.next())
        .await
        .unwrap()
        .unwrap();

    let build = |seq: u32, tsval: u32, payload: &[u8]| {
        let mut header = etherparse::TcpHeader::new(client_port, 39643, seq, 4096);
        header.ack = true;
        header.acknowledgment_number = server_seq;
        header.set_options(&[Opt::Timestamp(tsval, 0)]).unwrap();
        let mut packet = Vec::new();
        etherparse::PacketBuilder::ipv6(src, dst, 64)
            .tcp_header(header)
            .write(&mut packet, payload)
            .unwrap();
        Packet::new(packet)
    };
    let mut client_seq = initial_seq + 1;
    input.send(build(client_seq, 40_000, &[])).await.unwrap();
    let block = vec![0xa7u8; 1024];
    let mut advertised_window = u32::MAX;
    let mut total = 0usize;
    let mut window_zero = false;
    for frame_index in 0..850_u32 {
        let payload_length = if advertised_window == u32::MAX {
            block.len()
        } else {
            block.len().min(advertised_window as usize)
        };
        if payload_length == 0 {
            window_zero = true;
            break;
        }
        input
            .send(build(
                client_seq,
                41_000 + frame_index,
                &block[..payload_length],
            ))
            .await
            .unwrap();
        client_seq += payload_length as u32;
        total += payload_length;
        let (next_window, ack_tsecr) =
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let frame = output.next().await.unwrap().unwrap();
                    let parsed =
                        etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
                    let Some(etherparse::TransportSlice::Tcp(reply)) =
                        parsed.transport
                    else {
                        continue;
                    };
                    assert!(
                        !reply.rst(),
                        "receive-buffer pressure reset connection"
                    );
                    if reply.ack() && reply.acknowledgment_number() == client_seq {
                        let ts = reply
                            .options_iterator()
                            .filter_map(Result::ok)
                            .find_map(|opt| match opt {
                                Opt::Timestamp(_, echoed) => Some(echoed),
                                _ => None,
                            });
                        return (u32::from(reply.window_size()) * 8, ts);
                    }
                }
            })
            .await
            .expect("receive pressure ACK was not observed");
        advertised_window = next_window;
        if frame_index % 64 == 0 || advertised_window == 0 {
            eprintln!(
                "rx pressure: bytes={total} window={advertised_window} tsecr={ack_tsecr:?}"
            );
        }
        if advertised_window == 0 {
            window_zero = true;
            break;
        }
    }
    assert!(
        window_zero,
        "never observed an actual server-advertised zero receive window (accepted {total} bytes, remaining window {advertised_window})"
    );

    // A zero-length in-window ACK may still advance recent TSval even
    // while no application data fits. The next 1-byte data segment must
    // not inherit that privilege because the advertised window is zero.
    input.send(build(client_seq, 48_000, &[])).await.unwrap();
    // Data at a genuinely advertised zero window cannot advance ACK
    // or poison recent Timestamp, whether it is a duplicate, a future
    // segment, or an overlap with the previously acknowledged byte.
    for (seq, tsval, byte) in [
        (client_seq, 75_000, 0x22),
        (client_seq, 76_000, 0x23),
        (client_seq + 8, 77_000, 0x24),
        (client_seq - 1, 78_000, 0x25),
    ] {
        input.send(build(seq, tsval, &[byte])).await.unwrap();
    }
    let rejected_probe = tokio::time::timeout(Duration::from_millis(120), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(reply)) = parsed.transport
            else {
                continue;
            };
            assert!(!reply.rst(), "zero-window TCP probe reset connection");
            if reply.ack() && reply.acknowledgment_number() != client_seq {
                return true;
            }
        }
    })
    .await;
    assert!(
        rejected_probe.is_err(),
        "zero-window duplicate, future or overlap advanced ACK"
    );
    let mut readback = vec![0; 32 * 1024];
    let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut readback))
        .await
        .expect("receive-buffer recovery read timed out")
        .expect("stream read failed");
    assert!(n > 0);
    assert!(
        readback[..n].iter().all(|byte| *byte == 0xa7),
        "rejected zero-window byte was delivered to application"
    );
    eprintln!("zero-window recovery: accepted={total}, freed={n}");
    let reopened_window = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(reply)) = parsed.transport
            else {
                continue;
            };
            if reply.ack()
                && reply.acknowledgment_number() == client_seq
                && reply.window_size() > 0
            {
                return reply.window_size();
            }
        }
    })
    .await
    .expect("application read did not reopen the advertised TCP receive window");
    eprintln!("server receive window reopened: {reopened_window} units");
    // Retransmit the rejected byte using a *newer than valid last TSval*,
    // but still older than the high-TS rejected zero-window probe.
    // Pinned gVisor checks receive-window acceptability *before* updating
    // recent TSval; observing TSecr=75000 here would reveal metadata
    // poisoning by rejected data.
    input
        .send(build(client_seq, 50_000, &[0xb8]))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(reply)) = parsed.transport
            else {
                continue;
            };
            assert!(!reply.rst());
            if reply.ack() && reply.acknowledgment_number() == client_seq + 1 {
                let echoed = reply
                    .options_iterator()
                    .filter_map(Result::ok)
                    .find_map(|opt| match opt {
                        Opt::Timestamp(_, echo) => Some(echo),
                        _ => None,
                    });
                eprintln!("post-zero-window ACK: tsecr={echoed:?}");
                assert_eq!(
                    echoed,
                    Some(50_000),
                    "rejected zero-window payload wrongly updated recent TSecr"
                );
                break;
            }
        }
    })
    .await
    .expect("reopened-window retransmission not ACKed");
    // Simulate four consecutive missing TCP data segments, with their
    // retransmissions arriving in reverse order and the first prefix
    // last. Neither the cumulative ACK nor recent TSecr may advance
    // prematurely; the whole burst must be byte-perfect after repair.
    let post_seq = client_seq + 1;
    let chunks: [&[u8]; 5] = [b"gap0", b"gap1", b"gap2", b"gap3", b"tail"];
    for index in [4_usize, 2, 3, 1] {
        input
            .send(build(
                post_seq + (index * 4) as u32,
                85_000 + index as u32,
                chunks[index],
            ))
            .await
            .unwrap();
        let premature = tokio::time::timeout(Duration::from_millis(35), async {
            loop {
                let frame = output.next().await.unwrap().unwrap();
                let parsed =
                    etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
                let Some(etherparse::TransportSlice::Tcp(reply)) = parsed.transport
                else {
                    continue;
                };
                assert!(!reply.rst());
                if reply.ack() && reply.acknowledgment_number() > post_seq {
                    return true;
                }
            }
        })
        .await;
        assert!(
            premature.is_err(),
            "loss-burst suffix ACKed before missing prefix {index}"
        );
    }
    input
        .send(build(post_seq, 50_010, chunks[0]))
        .await
        .unwrap();
    let merged_ack =
        post_seq + chunks.iter().map(|chunk| chunk.len() as u32).sum::<u32>();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(reply)) = parsed.transport
            else {
                continue;
            };
            assert!(!reply.rst());
            if reply.ack() && reply.acknowledgment_number() == merged_ack {
                let echoed = reply
                    .options_iterator()
                    .filter_map(Result::ok)
                    .find_map(|opt| match opt {
                        Opt::Timestamp(_, echo) => Some(echo),
                        _ => None,
                    });
                assert_eq!(
                    echoed,
                    Some(50_010),
                    "gap repair TSecr poisoned by tail"
                );
                break;
            }
        }
    })
    .await
    .expect("post-window gap repair ACK missing");
    input.send(build(merged_ack, 50_020, b"Z")).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(reply)) = parsed.transport
            else {
                continue;
            };
            assert!(!reply.rst());
            if reply.ack() && reply.acknowledgment_number() == merged_ack + 1 {
                let echoed = reply
                    .options_iterator()
                    .filter_map(Result::ok)
                    .find_map(|opt| match opt {
                        Opt::Timestamp(_, echo) => Some(echo),
                        _ => None,
                    });
                assert_eq!(echoed, Some(50_020), "post-gap fresh TSecr regressed");
                break;
            }
        }
    })
    .await
    .expect("post-window fresh data ACK missing");
    // Drain the entire application stream and prove rejected probes did
    // not leak or alter the ordered accepted retransmit and gap-repair.
    let remaining = total - n;
    let mut remainder =
        vec![
            0;
            remaining
                + 1
                + chunks.iter().map(|chunk| chunk.len()).sum::<usize>()
                + 1
        ];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut remainder))
        .await
        .expect("buffered data never fully drained")
        .expect("post-window stream read failed");
    assert!(remainder[..remaining].iter().all(|byte| *byte == 0xa7));
    assert_eq!(remainder[remaining], 0xb8, "zero-window payload leaked");
    let actual_chunks = &remainder[remaining + 1..remainder.len() - 1];
    assert_eq!(
        actual_chunks,
        chunks.concat().as_slice(),
        "loss-burst reassembly order changed"
    );
    assert_eq!(remainder.last().copied(), Some(b'Z'));
    // Isolate an 8 KiB application downlink from the real namespace
    // relay's TCP-copy path: smoltcp must segment it into MTU-sized
    // outgoing TCP payloads even when written with one write_all call.
    use tokio::io::AsyncWriteExt;
    let bulk_downlink = vec![0x5a; 8 * 1024];
    tokio::time::timeout(Duration::from_secs(2), stream.write_all(&bulk_downlink))
        .await
        .expect("8 KiB application downlink write stalled")
        .expect("8 KiB application downlink write failed");
    let mut received_downlink = Vec::with_capacity(bulk_downlink.len());
    tokio::time::timeout(Duration::from_secs(2), async {
        while received_downlink.len() < bulk_downlink.len() {
            let frame = output.next().await.unwrap().unwrap();
            assert!(frame.data().len() <= 1500, "smoltcp output exceeded MTU");
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(reply)) = parsed.transport
            else {
                continue;
            };
            if reply.payload().is_empty() {
                continue;
            }
            assert_eq!(
                reply.sequence_number(),
                server_seq + received_downlink.len() as u32,
                "downlink TCP segment sequence gap"
            );
            received_downlink.extend_from_slice(reply.payload());
        }
    })
    .await
    .expect("smoltcp failed to segment 8 KiB downlink");
    assert_eq!(
        received_downlink, bulk_downlink,
        "8 KiB segmented payload corrupted"
    );
    tokio::time::timeout(Duration::from_secs(2), listener.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn xray_tcp_timestamp_large_peer_mss_segments_fit_tun_mtu() {
    use etherparse::TcpOptionElement as Opt;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    const MTU: usize = 1400;
    let (stack, mut listener, _udp) =
        NetStack::new_with_mtu_xray_tun_compat(MTU).unwrap();
    let (mut input, mut output) = stack.split();
    let src = [0x79; 16];
    let dst = [0x7a; 16];
    let client_port = 46281;
    let client_isn = 16_000_u32;
    let wire = |seq: u32, ack: Option<u32>, payload: &[u8]| {
        let mut header =
            etherparse::TcpHeader::new(client_port, 39643, seq, u16::MAX);
        header.syn = ack.is_none();
        if let Some(ack) = ack {
            header.ack = true;
            header.acknowledgment_number = ack;
        }
        let mut options = vec![Opt::Timestamp(50_000, 0)];
        if ack.is_none() {
            // Linux advertises an MSS larger than the server's 1400-byte
            // TUN path; smoltcp must account for the *extra* 12-byte TCP
            // Timestamp option rather than sizing to just the base header.
            options.insert(0, Opt::MaximumSegmentSize(1460));
        }
        header.set_options(&options).unwrap();
        let mut frame = Vec::new();
        etherparse::PacketBuilder::ipv6(src, dst, 64)
            .tcp_header(header)
            .write(&mut frame, payload)
            .unwrap();
        Packet::new(frame)
    };

    input.send(wire(client_isn, None, &[])).await.unwrap();
    let synack = tokio::time::timeout(Duration::from_secs(1), output.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let parsed = etherparse::SlicedPacket::from_ip(synack.data()).unwrap();
    let Some(etherparse::TransportSlice::Tcp(header)) = parsed.transport else {
        panic!("missing SYN-ACK");
    };
    assert!(header.syn() && header.ack());
    let server_seq = header.sequence_number() + 1;
    input
        .send(wire(client_isn + 1, Some(server_seq), &[]))
        .await
        .unwrap();
    let mut stream = tokio::time::timeout(Duration::from_secs(1), listener.next())
        .await
        .unwrap()
        .unwrap();
    let content = vec![0x5au8; 8192];
    tokio::time::timeout(Duration::from_secs(1), stream.write_all(&content))
        .await
        .expect("single 8 KiB downlink write stalled")
        .unwrap();

    let mut offset = 0;
    tokio::time::timeout(Duration::from_secs(2), async {
        while offset < content.len() {
            let packet = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(packet.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport else {
                continue;
            };
            if tcp.payload().is_empty() {
                continue;
            }
            assert!(
                packet.data().len() <= MTU,
                "emitted {}-byte Timestamp TCP packet beyond {MTU}-byte TUN MTU, segment data={}",
                packet.data().len(), tcp.payload().len()
            );
            assert_eq!(tcp.sequence_number(), server_seq + offset as u32,
                "TCP downlink sequence gap");
            assert_eq!(tcp.payload(), &content[offset..offset + tcp.payload().len()]);
            offset += tcp.payload().len();
        }
    }).await.expect("full 8 KiB server downlink never emitted");
    assert_eq!(offset, 8192);
    tokio::time::timeout(Duration::from_secs(1), listener.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn xray_tcp_tsecr_out_of_order_gap_repair_matches_ack_frontier() {
    use etherparse::TcpOptionElement as Opt;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    let (stack, mut listener, _udp) =
        NetStack::new_with_mtu_xray_tun_compat(1500).unwrap();
    let (mut input, mut output) = stack.split();
    let source = [0x56; 16];
    let target = [0x57; 16];
    let port = 46890;
    let client_isn = 80_000u32;
    let build = |seq: u32, ack: Option<u32>, ts: u32, bytes: &[u8]| {
        let mut header = etherparse::TcpHeader::new(port, 39643, seq, 4096);
        header.syn = ack.is_none();
        if let Some(ack) = ack {
            header.ack = true;
            header.acknowledgment_number = ack;
        }
        header.set_options(&[Opt::Timestamp(ts, 0)]).unwrap();
        let mut wire = Vec::new();
        etherparse::PacketBuilder::ipv6(source, target, 64)
            .tcp_header(header)
            .write(&mut wire, bytes)
            .unwrap();
        Packet::new(wire)
    };
    input
        .send(build(client_isn, None, 40_000, &[]))
        .await
        .unwrap();
    let synack = tokio::time::timeout(Duration::from_secs(1), output.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let parsed = etherparse::SlicedPacket::from_ip(synack.data()).unwrap();
    let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport else {
        panic!("missing SYN-ACK");
    };
    assert!(tcp.syn() && tcp.ack());
    let server_seq = tcp.sequence_number().wrapping_add(1);
    let mut stream = tokio::time::timeout(Duration::from_secs(1), listener.next())
        .await
        .unwrap()
        .unwrap();
    let start = client_isn + 1;
    input
        .send(build(start, Some(server_seq), 40_000, &[]))
        .await
        .unwrap();
    let first = b"gap-front";
    let tail = b"ooo-payload";
    input
        .send(build(
            start + first.len() as u32,
            Some(server_seq),
            50_000,
            tail,
        ))
        .await
        .unwrap();
    // A gap cannot deliver the tail or advance the cumulative ACK.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            stream.read(&mut [0u8; 32])
        )
        .await
        .is_err()
    );
    input
        .send(build(start, Some(server_seq), 41_000, first))
        .await
        .unwrap();
    let mut bytes = vec![0u8; first.len() + tail.len()];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut bytes))
        .await
        .expect("repaired gap not delivered")
        .expect("stream failed");
    assert_eq!(bytes, [first.as_slice(), tail.as_slice()].concat());
    let repaired_ack = start + bytes.len() as u32;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport else {
                continue;
            };
            if tcp.ack() && tcp.acknowledgment_number() == repaired_ack {
                let recent =
                    tcp.options_iterator()
                        .filter_map(Result::ok)
                        .find_map(|opt| match opt {
                            Opt::Timestamp(_, recent) => Some(recent),
                            _ => None,
                        });
                assert_eq!(
                    recent,
                    Some(41_000),
                    "gap-tail timestamp poisoned TSecr"
                );
                break;
            }
        }
    })
    .await
    .expect("repaired gap did not produce cumulative ACK");
    // Sending a newer in-order TSval *after* the buffered tail must advance
    // TSecr. This failed when the old metadata cursor stopped at the head.
    let after = b"after-gap";
    input
        .send(build(repaired_ack, Some(server_seq), 42_000, after))
        .await
        .unwrap();
    let mut delivered = vec![0; after.len()];
    tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut delivered))
        .await
        .expect("post-gap data stalled")
        .expect("post-gap read failed");
    assert_eq!(delivered, after);
    let after_ack = repaired_ack + after.len() as u32;
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let frame = output.next().await.unwrap().unwrap();
            let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport else {
                continue;
            };
            if tcp.ack() && tcp.acknowledgment_number() == after_ack {
                let recent =
                    tcp.options_iterator()
                        .filter_map(Result::ok)
                        .find_map(|opt| match opt {
                            Opt::Timestamp(_, recent) => Some(recent),
                            _ => None,
                        });
                assert_eq!(recent, Some(42_000));
                break;
            }
        }
    })
    .await
    .expect("post-gap cumulative ACK missing");
    tokio::time::timeout(Duration::from_secs(1), listener.shutdown())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn xray_tcp_timestamp_tsecr_recent_is_not_regressed_by_older_data() {
    use etherparse::TcpOptionElement as Opt;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    // Exercise the actual Xray TUN packet pump and smoltcp reply checksum,
    // not just the per-flow sequence/timestamp comparison helper.
    for (syn_ts, first_ts, second_ts, third_ts, second_echo) in [
        (40_000u32, 41_000u32, 40_001u32, 42_000u32, 41_000u32),
        (u32::MAX - 15, u32::MAX - 7, 8, u32::MAX - 1, 8),
    ] {
        let (stack, mut listener, _udp) =
            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap();
        let (mut input, mut output) = stack.split();
        let source = [0x53; 16];
        let target = [0x54; 16];
        let port = 46770;
        let cisn = 80_000u32;
        let mut syn = etherparse::TcpHeader::new(port, 39643, cisn, 4096);
        syn.syn = true;
        syn.set_options(&[Opt::Timestamp(syn_ts, 0)]).unwrap();
        let mut wire = Vec::new();
        etherparse::PacketBuilder::ipv6(source, target, 64)
            .tcp_header(syn)
            .write(&mut wire, &[])
            .unwrap();
        input.send(Packet::new(wire)).await.unwrap();
        let syn_ack =
            tokio::time::timeout(Duration::from_millis(700), output.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        let sliced = etherparse::SlicedPacket::from_ip(syn_ack.data()).unwrap();
        let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport else {
            panic!("expected SYN-ACK");
        };
        assert!(tcp.syn() && tcp.ack());
        assert!(tcp.options_iterator().filter_map(Result::ok).any(
            |option| matches!(option, Opt::Timestamp(_, echoed) if echoed == syn_ts)
        ));
        let server_seq = tcp.sequence_number().wrapping_add(1);
        let mut stream =
            tokio::time::timeout(Duration::from_millis(700), listener.next())
                .await
                .unwrap()
                .expect("listener ended");
        let send = |seq: u32, ts: u32, bytes: &[u8]| {
            let mut header = etherparse::TcpHeader::new(port, 39643, seq, 4096);
            header.ack = true;
            header.acknowledgment_number = server_seq;
            header.set_options(&[Opt::Timestamp(ts, 0)]).unwrap();
            let mut packet = Vec::new();
            etherparse::PacketBuilder::ipv6(source, target, 64)
                .tcp_header(header)
                .write(&mut packet, bytes)
                .unwrap();
            Packet::new(packet)
        };
        let mut client_seq = cisn + 1;
        input.send(send(client_seq, syn_ts, &[])).await.unwrap();
        for (data, timestamp, expected_echo) in [
            (b"recent-first".as_slice(), first_ts, first_ts),
            (b"recent-older".as_slice(), second_ts, second_echo),
            (
                b"recent-third".as_slice(),
                third_ts,
                if second_ts == 8 {
                    second_echo
                } else {
                    third_ts
                },
            ),
        ] {
            input.send(send(client_seq, timestamp, data)).await.unwrap();
            let mut received = vec![0; data.len()];
            tokio::time::timeout(
                Duration::from_millis(750),
                stream.read_exact(&mut received),
            )
            .await
            .expect("data not accepted")
            .expect("read failed");
            assert_eq!(received, data);
            client_seq += data.len() as u32;
            tokio::time::timeout(Duration::from_millis(750), async {
                loop {
                    let frame = output.next().await.unwrap().unwrap();
                    let parsed =
                        etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
                    let Some(etherparse::TransportSlice::Tcp(tcp)) =
                        parsed.transport
                    else {
                        continue;
                    };
                    if tcp.ack() && tcp.acknowledgment_number() == client_seq {
                        let ts = tcp
                            .options_iterator()
                            .filter_map(Result::ok)
                            .find_map(|option| match option {
                                Opt::Timestamp(_, echoed) => Some(echoed),
                                _ => None,
                            });
                        assert_eq!(
                            ts,
                            Some(expected_echo),
                            "old TSval must not regress TSecr"
                        );
                        break;
                    }
                }
            })
            .await
            .expect("ACK with expected TSecr missing");
        }
        if second_ts != 8 {
            // Pinned gVisor ignores a far-ahead TCP sequence for recent-TS
            // purposes, but does update recent-TS on a valid sequence with
            // an impossible future ACK number. Neither may corrupt the
            // application stream or its subsequent cumulative ACK.
            for (index, seq_delta, ack_delta, bad_ts, fresh_ts, expected_tsecr) in [
                (0, 0x20_0000, 0, 61_000, 42_010, 42_010),
                (1, 0, 0x20_0000, 62_000, 42_020, 62_000),
            ] {
                let mut abnormal = etherparse::TcpHeader::new(
                    port,
                    39643,
                    client_seq.wrapping_add(seq_delta),
                    4096,
                );
                abnormal.ack = true;
                abnormal.acknowledgment_number = server_seq.wrapping_add(ack_delta);
                abnormal.set_options(&[Opt::Timestamp(bad_ts, 0)]).unwrap();
                let mut raw = Vec::new();
                etherparse::PacketBuilder::ipv6(source, target, 64)
                    .tcp_header(abnormal)
                    .write(&mut raw, &[])
                    .unwrap();
                input.send(Packet::new(raw)).await.unwrap();
                let payload = format!("timestamp-post-abnormal-{index}");
                input
                    .send(send(client_seq, fresh_ts, payload.as_bytes()))
                    .await
                    .unwrap();
                let mut received = vec![0; payload.len()];
                tokio::time::timeout(
                    Duration::from_secs(1),
                    stream.read_exact(&mut received),
                )
                .await
                .expect("abnormal ACK prevented valid TCP data")
                .expect("post-abnormal read failed");
                assert_eq!(received, payload.as_bytes());
                client_seq += payload.len() as u32;
                tokio::time::timeout(Duration::from_secs(1), async {
                    loop {
                        let frame = output.next().await.unwrap().unwrap();
                        let parsed = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
                        let Some(etherparse::TransportSlice::Tcp(tcp)) = parsed.transport else {
                            continue;
                        };
                        if tcp.ack() && tcp.acknowledgment_number() == client_seq {
                            let echoed = tcp.options_iterator().filter_map(Result::ok)
                                .find_map(|option| match option {
                                    Opt::Timestamp(_, value) => Some(value),
                                    _ => None,
                                });
                            assert_eq!(echoed, Some(expected_tsecr),
                                "unexpected TSecr after abnormal seq/ACK case {index}");
                            break;
                        }
                    }
                }).await.expect("post-abnormal cumulative ACK missing");
            }
        }
        tokio::time::timeout(Duration::from_secs(1), listener.shutdown())
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn xray_tcp_timestamp_negotiates_only_if_syn_offers_option() {
    use etherparse::TcpOptionElement as Opt;
    use std::time::Duration;

    for xray in [false, true] {
        for offered in [false, true] {
            let (stack, mut listener, _udp) = if xray {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut input, mut output) = stack.split();
            let mut syn = etherparse::TcpHeader::new(45171, 39643, 17_001, 4096);
            syn.syn = true;
            if offered {
                syn.set_options(&[Opt::Timestamp(15_000, 0)]).unwrap();
            }
            let mut wire = Vec::new();
            etherparse::PacketBuilder::ipv6([0x51; 16], [0x52; 16], 64)
                .tcp_header(syn)
                .write(&mut wire, &[])
                .unwrap();
            input.send(Packet::new(wire)).await.unwrap();
            let frame =
                tokio::time::timeout(Duration::from_millis(700), output.next())
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            let sliced = etherparse::SlicedPacket::from_ip(frame.data()).unwrap();
            let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport else {
                panic!("no TCP SYN-ACK");
            };
            assert!(tcp.syn() && tcp.ack());
            let timestamp =
                tcp.options_iterator()
                    .filter_map(Result::ok)
                    .find_map(|option| match option {
                        Opt::Timestamp(tsval, tsecr) => Some((tsval, tsecr)),
                        _ => None,
                    });
            assert_eq!(
                timestamp.is_some(),
                xray && offered,
                "xray={xray}, offered={offered}"
            );
            if let Some((_, tsecr)) = timestamp {
                assert_eq!(tsecr, 15_000);
            }
            tokio::time::timeout(Duration::from_millis(700), listener.next())
                .await
                .unwrap()
                .expect("listener ended");
            tokio::time::timeout(Duration::from_millis(700), listener.shutdown())
                .await
                .unwrap()
                .unwrap();
        }
    }
}

#[tokio::test]
async fn established_ipv6_tcp_timestamp_negotiation_replay_and_recovery() {
    use etherparse::TcpOptionElement as Opt;
    use tokio::io::AsyncReadExt;

    // Only explicit Xray TUN enables a Timestamp generator. The default
    // stack keeps declining Timestamp. Neither mode may deliver an old
    // TCP sequence replay to the application a second time; this is not
    // evidence for full PAWS stale-TSval filtering.
    let source = [0x3f; 16];
    let destination = [0x40; 16];
    for xray in [false, true] {
        for (chained, offered_syn_ts) in [
            (false, 40_000u32),
            (true, 40_000u32),
            (false, u32::MAX - 15),
            (true, u32::MAX - 15),
        ] {
            let (stack, mut listener, _udp) = if xray {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut input, mut output) = stack.split();
            let port = if chained { 46391 } else { 46390 };
            let mut syn = etherparse::TcpHeader::new(port, 80, 1000, 4096);
            syn.syn = true;
            syn.set_options(&[Opt::Timestamp(offered_syn_ts, 0)])
                .unwrap();
            let mut syn_wire = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(syn)
                .write(&mut syn_wire, &[])
                .unwrap();
            input.send(Packet::new(syn_wire)).await.unwrap();
            let syn_ack = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                output.next(),
            )
            .await
            .expect("TCP Timestamp SYN-ACK timed out")
            .expect("stack output closed")
            .expect("stack output failed");
            let server_seq = match etherparse::SlicedPacket::from_ip(syn_ack.data())
                .expect("invalid timestamp SYN-ACK")
                .transport
            {
                Some(etherparse::TransportSlice::Tcp(tcp)) => {
                    assert!(tcp.syn() && tcp.ack());
                    let ts = tcp.options_iterator().filter_map(Result::ok).find_map(
                        |option| match option {
                            Opt::Timestamp(value, echoed) => Some((value, echoed)),
                            _ => None,
                        },
                    );
                    assert_eq!(
                        ts.is_some(),
                        xray,
                        "only Xray TUN may negotiate Timestamp"
                    );
                    if let Some((_, echoed)) = ts {
                        assert_eq!(
                            echoed, offered_syn_ts,
                            "SYN-ACK TSecr must echo SYN TSval"
                        );
                    }
                    tcp.sequence_number().wrapping_add(1)
                }
                _ => panic!("TCP timestamp test expected SYN-ACK"),
            };
            let mut stream = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                listener.next(),
            )
            .await
            .expect("timestamp offered connection not accepted")
            .expect("timestamp TCP listener ended");
            let segment = |seq: u32, payload: &[u8]| {
                let mut wire = Vec::new();
                etherparse::PacketBuilder::ipv6(source, destination, 64)
                    .tcp(port, 80, seq, 4096)
                    .ack(server_seq)
                    .write(&mut wire, payload)
                    .unwrap();
                wire
            };
            let fragment = |tcp: &[u8], ident: u32| {
                let options = if chained {
                    vec![
                        etherparse::ip_number::IPV6_DEST_OPTIONS.0,
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                        etherparse::ip_number::TCP.0,
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                    ]
                } else {
                    vec![etherparse::ip_number::TCP.0, 0, 1, 4, 0, 0, 0, 0]
                };
                let fragmentable = [options.as_slice(), tcp].concat();
                let split = options.len() + 8;
                let make = |tail: &[u8], offset: usize, more: bool| {
                    let header = etherparse::Ipv6Header {
                        payload_length: (8 + tail.len()) as u16,
                        next_header: etherparse::ip_number::IPV6_FRAG,
                        hop_limit: 64,
                        source,
                        destination,
                        ..Default::default()
                    };
                    let frag = etherparse::Ipv6FragmentHeader::new(
                        etherparse::ip_number::IPV6_DEST_OPTIONS,
                        etherparse::IpFragOffset::try_new((offset / 8) as u16)
                            .unwrap(),
                        more,
                        ident,
                    );
                    [
                        header.to_bytes().as_slice(),
                        frag.to_bytes().as_slice(),
                        tail,
                    ]
                    .concat()
                };
                [
                    make(&fragmentable[..split], 0, true),
                    make(&fragmentable[split..], split, false),
                ]
            };
            let ack = segment(1001, &[]);
            input.send(Packet::new(ack)).await.unwrap();
            let first = b"non-negotiated-timestamp";
            let wire = segment(1001, first);
            let fragments = fragment(&wire[40..], 0x7766_8800);
            input.send(Packet::new(fragments[1].clone())).await.unwrap();
            input.send(Packet::new(fragments[0].clone())).await.unwrap();
            let mut received = vec![0u8; first.len()];
            tokio::time::timeout(
                std::time::Duration::from_millis(500),
                stream.read_exact(&mut received),
            )
            .await
            .expect("first TCP timestamp-fallback read timed out")
            .expect("first TCP timestamp-fallback read failed");
            assert_eq!(received, first);
            // Replay exactly the *same TCP bytes and sequence*, under a
            // fresh IPv6 Fragment ID so reassembly doesn't hide the replay.
            let duplicate = fragment(&wire[40..], 0x7766_8801);
            input.send(Packet::new(duplicate[1].clone())).await.unwrap();
            input.send(Packet::new(duplicate[0].clone())).await.unwrap();
            let mut extra = [0u8; 1];
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(60),
                    stream.read(&mut extra)
                )
                .await
                .is_err(),
                "old-sequence replay duplicated application data, xray={xray}, chained={chained}"
            );
            let second = b"fresh-after-old-tcp-sequence";
            let wire2 = segment(1001 + first.len() as u32, second);
            let fragments2 = fragment(&wire2[40..], 0x7766_8802);
            input
                .send(Packet::new(fragments2[1].clone()))
                .await
                .unwrap();
            input
                .send(Packet::new(fragments2[0].clone()))
                .await
                .unwrap();
            let mut continued = vec![0u8; second.len()];
            tokio::time::timeout(
                std::time::Duration::from_millis(500),
                stream.read_exact(&mut continued),
            )
            .await
            .expect("timestamp fallback continuation timed out")
            .expect("timestamp fallback continuation read failed");
            assert_eq!(continued, second);

            // Invalid peer behavior, intentionally: after explicitly
            // declining TS during SYN-ACK, a remote TCP data segment
            // nonetheless contains a Timestamp option with a TSval
            // near the 32-bit boundary. Whether the stack ignores
            // this segment or accepts it, a standards-compliant
            // retransmission without unnegotiated TS must still work.
            let anomalous = b"unexpected-ts-fallback";
            let anomalous_seq = 1001 + first.len() as u32 + second.len() as u32;
            let mut invalid_ts =
                etherparse::TcpHeader::new(port, 80, anomalous_seq, 4096);
            invalid_ts.ack = true;
            invalid_ts.acknowledgment_number = server_seq;
            invalid_ts
                .set_options(&[Opt::Timestamp(u32::MAX - 1, 0)])
                .unwrap();
            let mut invalid_packet = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(invalid_ts)
                .write(&mut invalid_packet, anomalous)
                .unwrap();
            let invalid_fragments = fragment(&invalid_packet[40..], 0x7766_8803);
            input
                .send(Packet::new(invalid_fragments[1].clone()))
                .await
                .unwrap();
            input
                .send(Packet::new(invalid_fragments[0].clone()))
                .await
                .unwrap();
            let mut observed = vec![0u8; anomalous.len()];
            let initially_delivered = match tokio::time::timeout(
                std::time::Duration::from_millis(120),
                stream.read_exact(&mut observed),
            )
            .await
            {
                Ok(result) => {
                    result.expect("unnegotiated TS read failed");
                    true
                }
                Err(_) => false,
            };
            if !initially_delivered {
                // Only retransmit the same still-unacknowledged TCP
                // sequence, without the unnegotiated TCP option.
                let legal = segment(anomalous_seq, anomalous);
                let legal_fragments = fragment(&legal[40..], 0x7766_8804);
                input
                    .send(Packet::new(legal_fragments[1].clone()))
                    .await
                    .unwrap();
                input
                    .send(Packet::new(legal_fragments[0].clone()))
                    .await
                    .unwrap();
                tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    stream.read_exact(&mut observed),
                )
                .await
                .expect("unnegotiated TS retransmission stalled")
                .expect("fallback TCP read failed");
            }
            assert_eq!(observed, anomalous, "xray={xray} chained={chained}");
            let final_data = b"legal-after-unnegotiated-ts";
            let final_wire =
                segment(anomalous_seq + anomalous.len() as u32, final_data);
            input.send(Packet::new(final_wire)).await.unwrap();
            let mut final_read = vec![0u8; final_data.len()];
            tokio::time::timeout(
                std::time::Duration::from_millis(500),
                stream.read_exact(&mut final_read),
            )
            .await
            .expect("legal follow-on data after unnegotiated TS stalled")
            .expect("legal follow-on TCP read failed");
            assert_eq!(final_read, final_data);
        }
    }
}

#[tokio::test]
async fn established_ipv6_tcp_sack_reneging_and_dsack_preserve_stream() {
    use etherparse::TcpOptionElement as Opt;
    use tokio::io::AsyncWriteExt;

    let source = [0x3d; 16];
    let destination = [0x3e; 16];
    let data: Vec<u8> = (0..2100).map(|i| (i * 37 + 11) as u8).collect();
    for xray in [false, true] {
        let (stack, mut listener, _udp) = if xray {
            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
        } else {
            NetStack::new()
        };
        let (mut input, mut output) = stack.split();
        let mut syn = etherparse::TcpHeader::new(46380, 80, 1000, 8192);
        syn.syn = true;
        syn.set_options(&[
            Opt::MaximumSegmentSize(536),
            Opt::SelectiveAcknowledgementPermitted,
        ])
        .unwrap();
        let mut wire = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp_header(syn)
            .write(&mut wire, &[])
            .unwrap();
        input.send(Packet::new(wire)).await.unwrap();
        let syn_ack = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            output.next(),
        )
        .await
        .expect("reneging SYN-ACK timed out")
        .expect("netstack output closed")
        .expect("netstack output error");
        let base = match etherparse::SlicedPacket::from_ip(syn_ack.data())
            .expect("invalid SACK SYN-ACK")
            .transport
        {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                assert!(tcp.syn() && tcp.ack());
                assert!(tcp.options_iterator().filter_map(Result::ok).any(
                    |opt| matches!(opt, Opt::SelectiveAcknowledgementPermitted)
                ));
                tcp.sequence_number().wrapping_add(1)
            }
            _ => panic!("SACK reneging expected TCP SYN-ACK"),
        };
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            listener.next(),
        )
        .await
        .expect("reneging accept timed out")
        .expect("reneging listener closed");
        let ack = |cumulative: u32, sack: Option<(u32, u32)>| {
            let mut tcp = etherparse::TcpHeader::new(46380, 80, 1001, 8192);
            tcp.ack = true;
            tcp.acknowledgment_number = cumulative;
            if let Some(bounds) = sack {
                tcp.set_options(&[Opt::SelectiveAcknowledgement(
                    bounds,
                    [None, None, None],
                )])
                .unwrap();
            }
            let mut bytes = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(tcp)
                .write(&mut bytes, &[])
                .unwrap();
            Packet::new(bytes)
        };
        input.send(ack(base, None)).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.write_all(&data),
        )
        .await
        .expect("SACK reneging initial write timed out")
        .expect("SACK reneging initial write failed");
        let mut observed = std::collections::BTreeMap::<usize, Vec<u8>>::new();
        let mut acked_first = false;
        tokio::time::timeout(std::time::Duration::from_millis(1500), async {
            while observed.len() < 3 {
                let frame = output
                    .next()
                    .await
                    .expect("reneging TCP output closed")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|packet| packet.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "reneging SYN flow reset");
                let Some(offset) = tcp.sequence_number().checked_sub(base) else {
                    continue;
                };
                if tcp.payload().is_empty() || offset as usize >= data.len() {
                    continue;
                }
                let offset = offset as usize;
                assert_eq!(
                    data.get(offset..offset + tcp.payload().len()),
                    Some(tcp.payload())
                );
                observed.insert(offset, tcp.payload().to_vec());
                if offset == 0 && !acked_first {
                    acked_first = true;
                    input
                        .send(ack(base + tcp.payload().len() as u32, None))
                        .await
                        .unwrap();
                }
            }
        })
        .await
        .expect("reneging requires three outgoing TCP segments");
        let offsets: Vec<_> = observed.keys().copied().collect();
        let (gap, reneged_at) = (offsets[1], offsets[2]);
        let sack = (
            base + reneged_at as u32,
            base + (reneged_at + observed[&reneged_at].len()) as u32,
        );
        // Report a *genuinely observed* later interval via SACK, then
        // simulate receiver memory pressure discarding it (reneging).
        observed.remove(&gap);
        for _ in 0..4 {
            input
                .send(ack(base + gap as u32, Some(sack)))
                .await
                .unwrap();
        }
        observed.remove(&reneged_at);
        let mut gap_retrans = false;
        tokio::time::timeout(std::time::Duration::from_millis(2500), async {
            while !gap_retrans {
                let frame = output
                    .next()
                    .await
                    .expect("reneging retransmit output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|packet| packet.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "reneging first retransmission reset");
                let Some(offset) = tcp.sequence_number().checked_sub(base) else {
                    continue;
                };
                if tcp.payload().is_empty() || offset as usize >= data.len() {
                    continue;
                }
                let offset = offset as usize;
                assert_eq!(
                    data.get(offset..offset + tcp.payload().len()),
                    Some(tcp.payload())
                );
                if offset == gap {
                    observed.insert(offset, tcp.payload().to_vec());
                    gap_retrans = true;
                } else if offset == reneged_at {
                    observed.insert(offset, tcp.payload().to_vec());
                }
            }
        })
        .await
        .expect("first missing TCP segment was not retransmitted");
        // Cumulative ACK advances only to the start of the discarded
        // former SACK range, and its SACK option is now absent.
        input
            .send(ack(base + reneged_at as u32, None))
            .await
            .unwrap();
        let mut contiguous = 0usize;
        let mut cumulative = reneged_at;
        tokio::time::timeout(std::time::Duration::from_secs(12), async {
            loop {
                while let Some(bytes) = observed.get(&contiguous) {
                    contiguous += bytes.len();
                }
                if contiguous > cumulative {
                    input
                        .send(ack(base + contiguous as u32, None))
                        .await
                        .unwrap();
                    cumulative = contiguous;
                }
                if contiguous == data.len() {
                    break;
                }
                let frame = output
                    .next()
                    .await
                    .expect("reneging recovery output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|packet| packet.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "reneging recovery reset");
                let Some(offset) = tcp.sequence_number().checked_sub(base) else {
                    continue;
                };
                if tcp.payload().is_empty() || offset as usize >= data.len() {
                    continue;
                }
                let offset = offset as usize;
                assert_eq!(
                    data.get(offset..offset + tcp.payload().len()),
                    Some(tcp.payload())
                );
                observed.insert(offset, tcp.payload().to_vec());
            }
        })
        .await
        .expect("sender did not retransmit reneged SACK data");
        assert_eq!(contiguous, data.len());
        assert!(
            observed.contains_key(&reneged_at),
            "reneged range was never retransmitted"
        );

        // Now test a *real duplicate*, not a fabricated DSACK: write a
        // short fresh server payload and deliberately withhold its ACK.
        // Only upon receiving a byte-identical retransmission do we
        // cumulatively ACK it and report the duplicated range in DSACK.
        let dsack_data = b"two-copies-before-dsack";
        stream.write_all(dsack_data).await.unwrap();
        let dsack_start = base + data.len() as u32;
        let mut copies = 0;
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            while copies < 2 {
                let frame = output
                    .next()
                    .await
                    .expect("DSACK retransmission output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|packet| packet.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "DSACK flow reset");
                if tcp.sequence_number() == dsack_start
                    && tcp.payload() == dsack_data
                {
                    copies += 1;
                }
            }
        })
        .await
        .expect("genuine DSACK requires two received copies");
        input
            .send(ack(
                dsack_start + dsack_data.len() as u32,
                Some((dsack_start, dsack_start + dsack_data.len() as u32)),
            ))
            .await
            .unwrap();
        let after = b"stream-continues-after-dsack";
        stream.write_all(after).await.unwrap();
        let mut delivered = Vec::new();
        tokio::time::timeout(std::time::Duration::from_millis(900), async {
            while delivered.len() < after.len() {
                let frame = output
                    .next()
                    .await
                    .expect("post-DSACK output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|packet| packet.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "post-DSACK flow reset");
                if tcp.sequence_number()
                    == dsack_start + dsack_data.len() as u32 + delivered.len() as u32
                {
                    delivered.extend_from_slice(tcp.payload());
                }
            }
        })
        .await
        .expect("no post-DSACK data");
        assert_eq!(delivered, after, "SACK reneging/DSACK corrupt xray={xray}");
    }
}

#[tokio::test]
async fn established_ipv6_tcp_sender_two_sack_holes_recover_after_partial_ack() {
    use etherparse::TcpOptionElement as Opt;
    use tokio::io::AsyncWriteExt;

    let source = [0x3b; 16];
    let destination = [0x3c; 16];
    let data: Vec<u8> = (0..3500).map(|i| (i * 37 + 11) as u8).collect();
    for (xray, sack_enabled) in
        [(false, true), (true, true), (false, false), (true, false)]
    {
        let (stack, mut listener, _udp) = if xray {
            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
        } else {
            NetStack::new()
        };
        let (mut input, mut output) = stack.split();
        let port = if sack_enabled { 46370 } else { 46371 };
        let mut syn = etherparse::TcpHeader::new(port, 80, 1000, 8192);
        syn.syn = true;
        let syn_opts = if sack_enabled {
            vec![
                Opt::MaximumSegmentSize(536),
                Opt::SelectiveAcknowledgementPermitted,
            ]
        } else {
            vec![Opt::MaximumSegmentSize(536)]
        };
        syn.set_options(&syn_opts).unwrap();
        let mut syn_packet = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp_header(syn)
            .write(&mut syn_packet, &[])
            .unwrap();
        input.send(Packet::new(syn_packet)).await.unwrap();
        let syn_ack = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            output.next(),
        )
        .await
        .expect("two-hole SYN-ACK timed out")
        .expect("TCP output ended")
        .expect("TCP packet failed");
        let base = match etherparse::SlicedPacket::from_ip(syn_ack.data())
            .expect("bad two-hole SYN-ACK")
            .transport
        {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                assert!(tcp.syn() && tcp.ack());
                assert_eq!(
                    tcp.options_iterator().filter_map(Result::ok).any(
                        |opt| matches!(opt, Opt::SelectiveAcknowledgementPermitted)
                    ),
                    sack_enabled,
                );
                tcp.sequence_number().wrapping_add(1)
            }
            _ => panic!("two-hole SYN did not receive TCP SYN-ACK"),
        };
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            listener.next(),
        )
        .await
        .expect("two-hole accept timed out")
        .expect("TCP listener closed");
        let ack = |cumulative: u32, sacks: &[(u32, u32)]| {
            let mut tcp = etherparse::TcpHeader::new(port, 80, 1001, 8192);
            tcp.ack = true;
            tcp.acknowledgment_number = cumulative;
            if let Some(first) = sacks.first().copied() {
                let mut remaining = [None; 3];
                remaining[0] = sacks.get(1).copied();
                tcp.set_options(&[Opt::SelectiveAcknowledgement(first, remaining)])
                    .unwrap();
            }
            let mut wire = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(tcp)
                .write(&mut wire, &[])
                .unwrap();
            Packet::new(wire)
        };
        input.send(ack(base, &[])).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.write_all(&data),
        )
        .await
        .expect("two-hole write timed out")
        .expect("two-hole write failed");

        // Collect five *distinct* valid data segments: first ACKed,
        // missing #1, observed #1, missing #2, observed #2.
        let mut pieces = std::collections::BTreeMap::new();
        tokio::time::timeout(std::time::Duration::from_millis(1800), async {
            while pieces.len() < 5 {
                let frame =
                    output.next().await.expect("two-hole output ended").unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "SACK sender reset, xray={xray}");
                let Some(offset) = tcp.sequence_number().checked_sub(base) else {
                    continue;
                };
                if tcp.payload().is_empty() || offset as usize >= data.len() {
                    continue;
                }
                let offset = offset as usize;
                assert_eq!(
                    data.get(offset..offset + tcp.payload().len()),
                    Some(tcp.payload())
                );
                pieces.insert(offset, tcp.payload().to_vec());
                if offset == 0 {
                    input
                        .send(ack(base + tcp.payload().len() as u32, &[]))
                        .await
                        .unwrap();
                }
            }
        })
        .await
        .expect("five distinct outgoing segments not observed");
        let offsets: Vec<_> = pieces.keys().copied().collect();
        let (hole1, hole2) = (offsets[1], offsets[3]);
        let block1 = (
            base + offsets[2] as u32,
            base + (offsets[2] + pieces[&offsets[2]].len()) as u32,
        );
        let block2 = (
            base + offsets[4] as u32,
            base + (offsets[4] + pieces[&offsets[4]].len()) as u32,
        );
        assert_eq!(block1.1, base + hole2 as u32);
        let first_len = pieces[&offsets[0]].len();
        assert_eq!(first_len, hole1);
        pieces.remove(&hole1);
        pieces.remove(&hole2);
        for _ in 0..4 {
            let sacks = if sack_enabled {
                vec![block2, block1]
            } else {
                vec![]
            };
            input.send(ack(base + hole1 as u32, &sacks)).await.unwrap();
        }
        let mut repaired1 = false;
        let mut repaired2 = false;
        let mut retransmission_order = Vec::new();
        tokio::time::timeout(std::time::Duration::from_millis(2600), async {
            while !repaired1 {
                let frame = output
                    .next()
                    .await
                    .expect("missing first retransmission")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "first SACK retransmission reset");
                let Some(offset) = tcp.sequence_number().checked_sub(base) else {
                    continue;
                };
                if tcp.payload().is_empty() || offset as usize >= data.len() {
                    continue;
                }
                let offset = offset as usize;
                assert_eq!(
                    data.get(offset..offset + tcp.payload().len()),
                    Some(tcp.payload())
                );
                pieces.insert(offset, tcp.payload().to_vec());
                if offset == hole1 {
                    repaired1 = true;
                    retransmission_order.push(1);
                }
                if offset == hole2 {
                    repaired2 = true;
                    retransmission_order.push(2);
                }
            }
        })
        .await
        .expect("first SACK hole not repaired");
        let mut contiguous = 0usize;
        while let Some(chunk) = pieces.get(&contiguous) {
            contiguous += chunk.len();
        }
        assert!(
            contiguous >= hole2,
            "first hole repair did not reach partial ACK"
        );
        // Deliberately send a *partial* cumulative ACK, stopping at hole
        // #2 even if its retransmission happened to arrive already.
        for _ in 0..4 {
            let sacks = if sack_enabled { vec![block2] } else { vec![] };
            input.send(ack(base + hole2 as u32, &sacks)).await.unwrap();
        }
        if !repaired2 {
            tokio::time::timeout(std::time::Duration::from_millis(2600), async {
                while !repaired2 {
                    let frame = output
                        .next()
                        .await
                        .expect("missing second retransmission")
                        .unwrap();
                    let Some(etherparse::TransportSlice::Tcp(tcp)) =
                        etherparse::SlicedPacket::from_ip(frame.data())
                            .ok()
                            .and_then(|ip| ip.transport)
                    else {
                        continue;
                    };
                    assert!(!tcp.rst(), "second SACK retransmission reset");
                    let Some(offset) = tcp.sequence_number().checked_sub(base)
                    else {
                        continue;
                    };
                    if tcp.payload().is_empty() || offset as usize >= data.len() {
                        continue;
                    }
                    let offset = offset as usize;
                    assert_eq!(
                        data.get(offset..offset + tcp.payload().len()),
                        Some(tcp.payload())
                    );
                    pieces.insert(offset, tcp.payload().to_vec());
                    if offset == hole2 {
                        repaired2 = true;
                        retransmission_order.push(2);
                    }
                }
            })
            .await
            .expect("second SACK hole not repaired after partial ACK");
        }
        let mut acked = hole2;
        tokio::time::timeout(std::time::Duration::from_millis(2600), async {
            loop {
                while let Some(chunk) = pieces.get(&contiguous) {
                    contiguous += chunk.len();
                }
                if contiguous > acked {
                    input
                        .send(ack(base + contiguous as u32, &[]))
                        .await
                        .unwrap();
                    acked = contiguous;
                }
                if contiguous == data.len() {
                    break;
                }
                let frame = output
                    .next()
                    .await
                    .expect("two-hole remainder missing")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                assert!(!tcp.rst(), "two-hole recovery reset");
                let Some(offset) = tcp.sequence_number().checked_sub(base) else {
                    continue;
                };
                if tcp.payload().is_empty() || offset as usize >= data.len() {
                    continue;
                }
                let offset = offset as usize;
                assert_eq!(
                    data.get(offset..offset + tcp.payload().len()),
                    Some(tcp.payload())
                );
                pieces.insert(offset, tcp.payload().to_vec());
            }
        })
        .await
        .expect("two-hole stream did not fully recover");
        assert_eq!(contiguous, data.len());
        assert!(repaired1 && repaired2, "both sender holes must be repaired");
        assert!(
            retransmission_order.contains(&1) && retransmission_order.contains(&2),
            "both holes require observed retransmissions"
        );
        let after = b"fresh-after-two-sack-holes";
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.write_all(after),
        )
        .await
        .expect("post-SACK writer stalled")
        .expect("post-SACK write failed");
        let mut continued = Vec::new();
        tokio::time::timeout(std::time::Duration::from_millis(900), async {
            while continued.len() < after.len() {
                let frame = output
                    .next()
                    .await
                    .expect("post-SACK output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                if tcp.sequence_number()
                    == base + data.len() as u32 + continued.len() as u32
                {
                    continued.extend_from_slice(tcp.payload());
                }
            }
        })
        .await
        .expect("post-SACK stream did not continue");
        assert_eq!(continued, after, "post-SACK data corrupted xray={xray}");
    }
}

#[tokio::test]
async fn established_ipv6_tcp_sender_handles_sack_gap_and_cumulative_recovery() {
    use etherparse::TcpOptionElement as Opt;
    use tokio::io::AsyncWriteExt;

    let source = [0x39; 16];
    let destination = [0x3a; 16];
    let data: Vec<u8> = (0..2100).map(|index| (index * 37 + 11) as u8).collect();
    for (xray, sack_enabled) in
        [(false, true), (true, true), (false, false), (true, false)]
    {
        let (stack, mut listener, _udp) = if xray {
            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
        } else {
            NetStack::new()
        };
        let (mut input, mut output) = stack.split();
        let port = if sack_enabled { 46360 } else { 46361 };
        let mut syn = etherparse::TcpHeader::new(port, 80, 1000, 8192);
        syn.syn = true;
        let options = if sack_enabled {
            vec![
                Opt::MaximumSegmentSize(536),
                Opt::SelectiveAcknowledgementPermitted,
            ]
        } else {
            vec![Opt::MaximumSegmentSize(536)]
        };
        syn.set_options(&options).unwrap();
        let mut syn_packet = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp_header(syn)
            .write(&mut syn_packet, &[])
            .unwrap();
        input.send(Packet::new(syn_packet)).await.unwrap();
        let syn_ack = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            output.next(),
        )
        .await
        .expect("no SYN-ACK for SACK sender")
        .expect("TCP packet engine closed")
        .expect("TCP packet error");
        let base = match etherparse::SlicedPacket::from_ip(syn_ack.data())
            .expect("invalid sender SYN-ACK")
            .transport
        {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                assert!(tcp.syn() && tcp.ack());
                assert_eq!(
                    tcp.options_iterator().filter_map(Result::ok).any(
                        |opt| matches!(opt, Opt::SelectiveAcknowledgementPermitted)
                    ),
                    sack_enabled
                );
                tcp.sequence_number().wrapping_add(1)
            }
            _ => panic!("sender SACK expected SYN-ACK"),
        };
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            listener.next(),
        )
        .await
        .expect("missing sender stream")
        .expect("TCP listener closed");
        let build_ack = |cumulative: u32, selective: Option<(u32, u32)>| {
            let mut tcp = etherparse::TcpHeader::new(port, 80, 1001, 8192);
            tcp.ack = true;
            tcp.acknowledgment_number = cumulative;
            if let Some(bounds) = selective {
                tcp.set_options(&[Opt::SelectiveAcknowledgement(
                    bounds,
                    [None, None, None],
                )])
                .unwrap();
            }
            let mut packet = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(tcp)
                .write(&mut packet, &[])
                .unwrap();
            Packet::new(packet)
        };
        input.send(build_ack(base, None)).await.unwrap();
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.write_all(&data),
        )
        .await
        .expect("outbound SACK data could not be queued")
        .expect("outbound SACK write failed");

        // Receive at least three distinct server->client data segments.
        // Cumulatively ACK only the very first, then simulate loss of the
        // next segment while a later one was *actually* received.
        let mut pieces = std::collections::BTreeMap::new();
        let mut first_ack_len = None;
        tokio::time::timeout(std::time::Duration::from_millis(1600), async {
            while pieces.len() < 3 {
                let frame = output
                    .next()
                    .await
                    .expect("sender TCP output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                if tcp.rst() {
                    panic!("outbound SACK stream reset, xray={xray}");
                }
                let Some(offset) = tcp.sequence_number().checked_sub(base) else {
                    continue;
                };
                if tcp.payload().is_empty() || offset as usize >= data.len() {
                    continue;
                }
                let offset = offset as usize;
                assert_eq!(
                    data.get(offset..offset + tcp.payload().len()),
                    Some(tcp.payload())
                );
                pieces.insert(offset, tcp.payload().to_vec());
                if offset == 0 && first_ack_len.is_none() {
                    first_ack_len = Some(tcp.payload().len());
                    input
                        .send(build_ack(base + tcp.payload().len() as u32, None))
                        .await
                        .unwrap();
                }
            }
        })
        .await
        .expect("did not obtain three distinct outbound TCP segments");
        let gap = first_ack_len.expect("missing first outbound TCP data");
        let (sacked_at, sacked_bytes) = pieces
            .iter()
            .find(|(offset, _)| **offset > gap)
            .expect("no later data to selectively acknowledge");
        let sacked = (
            base + *sacked_at as u32,
            base + (*sacked_at + sacked_bytes.len()) as u32,
        );
        for _ in 0..4 {
            input
                .send(build_ack(
                    base + gap as u32,
                    if sack_enabled { Some(sacked) } else { None },
                ))
                .await
                .unwrap();
        }
        // Fast retransmit / RTO may differ across netstacks; the lost
        // segment must eventually be retransmitted *unaltered*.
        tokio::time::timeout(std::time::Duration::from_millis(2000), async {
            loop {
                let frame = output
                    .next()
                    .await
                    .expect("sender recovery output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                if tcp.rst() {
                    panic!("SACK sender recovery reset, xray={xray}");
                }
                if tcp.sequence_number() == base + gap as u32
                    && !tcp.payload().is_empty()
                {
                    assert_eq!(
                        data.get(gap..gap + tcp.payload().len()),
                        Some(tcp.payload()),
                        "lost segment changed during retransmission, xray={xray}"
                    );
                    pieces.insert(gap, tcp.payload().to_vec());
                    break;
                }
                if let Some(offset) = tcp.sequence_number().checked_sub(base)
                    && !tcp.payload().is_empty()
                    && (offset as usize) < data.len()
                {
                    let offset = offset as usize;
                    assert_eq!(
                        data.get(offset..offset + tcp.payload().len()),
                        Some(tcp.payload())
                    );
                    pieces.insert(offset, tcp.payload().to_vec());
                }
            }
        })
        .await
        .expect("missing TCP retransmission for the unacknowledged hole");
        // Do not ACK data beyond what the synthetic client has received
        // contiguously. Remaining data can only be delivered after the
        // gap-repair ACK slides the cumulative right edge.
        let mut contiguous = 0usize;
        let mut acked = gap;
        tokio::time::timeout(std::time::Duration::from_millis(2600), async {
            loop {
                while let Some(payload) = pieces.get(&contiguous) {
                    contiguous += payload.len();
                }
                if contiguous > acked {
                    input
                        .send(build_ack(base + contiguous as u32, None))
                        .await
                        .unwrap();
                    acked = contiguous;
                }
                if contiguous == data.len() {
                    break;
                }
                let frame = output
                    .next()
                    .await
                    .expect("missing end of SACK Echo")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                if tcp.rst() {
                    panic!("SACK sender closed before data recovery, xray={xray}");
                }
                if let Some(offset) = tcp.sequence_number().checked_sub(base)
                    && !tcp.payload().is_empty()
                    && (offset as usize) < data.len()
                {
                    let offset = offset as usize;
                    assert_eq!(
                        data.get(offset..offset + tcp.payload().len()),
                        Some(tcp.payload())
                    );
                    pieces.insert(offset, tcp.payload().to_vec());
                }
            }
        })
        .await
        .expect("incomplete SACK sender recovery");
        assert_eq!(contiguous, data.len());
        let after = b"still-connected-after-sack";
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.write_all(after),
        )
        .await
        .expect("SACK sender blocked subsequent data")
        .expect("SACK sender failed subsequent write");
        let mut tail = Vec::new();
        tokio::time::timeout(std::time::Duration::from_millis(800), async {
            while tail.len() < after.len() {
                let frame = output
                    .next()
                    .await
                    .expect("SACK sender tail output ended")
                    .unwrap();
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|ip| ip.transport)
                else {
                    continue;
                };
                if tcp.sequence_number()
                    == base + data.len() as u32 + tail.len() as u32
                {
                    tail.extend_from_slice(tcp.payload());
                }
            }
        })
        .await
        .expect("no fresh TCP data after SACK recovery");
        assert_eq!(tail, after, "post-SACK stream corrupt xray={xray}");
    }
}

#[tokio::test]
async fn fragmented_ipv6_tcp_sack_gap_reassembles_once_and_is_negotiated() {
    use etherparse::TcpOptionElement as Opt;
    use tokio::io::AsyncReadExt;

    let source = [0x35; 16];
    let destination = [0x36; 16];
    for (xray, allow_sack) in
        [(false, true), (true, true), (false, false), (true, false)]
    {
        let (stack, mut listener, _udp) = if xray {
            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
        } else {
            NetStack::new()
        };
        let (mut input, mut output) = stack.split();
        let port = if allow_sack { 46350 } else { 46351 };
        let mut syn_header = etherparse::TcpHeader::new(port, 80, 1000, 4096);
        syn_header.syn = true;
        if allow_sack {
            syn_header
                .set_options(&[
                    Opt::MaximumSegmentSize(1200),
                    Opt::SelectiveAcknowledgementPermitted,
                ])
                .unwrap();
        } else {
            syn_header
                .set_options(&[Opt::MaximumSegmentSize(1200)])
                .unwrap();
        }
        let mut syn = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp_header(syn_header)
            .write(&mut syn, &[])
            .unwrap();
        input.send(Packet::new(syn)).await.unwrap();

        let syn_ack = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            output.next(),
        )
        .await
        .expect("missing SACK SYN-ACK")
        .expect("stack output closed")
        .expect("stack output failed");
        let server_seq = match etherparse::SlicedPacket::from_ip(syn_ack.data())
            .expect("invalid TCP SYN-ACK")
            .transport
        {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                assert!(tcp.syn() && tcp.ack());
                assert_eq!(
                    tcp.options_iterator().filter_map(Result::ok).any(
                        |option| matches!(
                            option,
                            Opt::SelectiveAcknowledgementPermitted
                        )
                    ),
                    allow_sack,
                    "SACK permission in SYN-ACK must reflect client's SYN, xray={xray}",
                );
                tcp.sequence_number().wrapping_add(1)
            }
            _ => panic!("expected TCP SYN-ACK"),
        };
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            listener.next(),
        )
        .await
        .expect("missing accepted SACK flow")
        .expect("listener closed");
        let fragment = |body: &[u8], offset: usize, more: bool, ident: u32| {
            let ip = etherparse::Ipv6Header {
                payload_length: (8 + body.len()) as u16,
                next_header: etherparse::ip_number::IPV6_FRAG,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            };
            let frag = etherparse::Ipv6FragmentHeader::new(
                etherparse::ip_number::TCP,
                etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                more,
                ident,
            );
            [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), body].concat()
        };
        let mut normal_ack = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(port, 80, 1001, 4096)
            .ack(server_seq)
            .write(&mut normal_ack, &[])
            .unwrap();
        input.send(Packet::new(normal_ack)).await.unwrap();

        let gap = b"lost-";
        let tail = b"later-fragmented-segment";
        let sack_bounds = (
            1001 + gap.len() as u32,
            1001 + gap.len() as u32 + tail.len() as u32,
        );
        let mut future_segment = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(port, 80, sack_bounds.0, 4096)
            .ack(server_seq)
            .write(&mut future_segment, tail)
            .unwrap();
        let later = &future_segment[40..];
        // The first segment is "lost" in this deterministic test.
        // The later TCP segment is complete but IPv6-fragmented and
        // delivered in reverse fragment order (eight TCP bytes first).
        input
            .send(Packet::new(fragment(&later[8..], 8, false, 0x5566_9901)))
            .await
            .unwrap();
        input
            .send(Packet::new(fragment(&later[..8], 0, true, 0x5566_9901)))
            .await
            .unwrap();

        let mut observed_dup_ack = false;
        let mut observed_sack = false;
        tokio::time::timeout(std::time::Duration::from_millis(600), async {
            while let Some(Ok(frame)) = output.next().await {
                let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|packet| packet.transport)
                else {
                    continue;
                };
                if tcp.ack() && tcp.acknowledgment_number() == 1001 {
                    observed_dup_ack = true;
                }
                for option in tcp.options_iterator().filter_map(Result::ok) {
                    if let Opt::SelectiveAcknowledgement(first, _) = option {
                        assert!(
                            allow_sack,
                            "unnegotiated SACK block leaked into output, xray={xray}"
                        );
                        assert_eq!(
                            first, sack_bounds,
                            "wrong selective range, xray={xray}"
                        );
                        observed_sack = true;
                    }
                }
                if observed_dup_ack && (!allow_sack || observed_sack) {
                    break;
                }
            }
        })
        .await
        .expect("missing cumulative ACK / SACK response to out-of-order data");
        assert!(observed_dup_ack);
        assert_eq!(observed_sack, allow_sack);
        let mut premature = [0u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(60),
                stream.read(&mut premature),
            )
            .await
            .is_err(),
            "out-of-order TCP data delivered to the application before gap repair"
        );

        let mut missing_segment = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(port, 80, 1001, 4096)
            .ack(server_seq)
            .write(&mut missing_segment, gap)
            .unwrap();
        let missing = &missing_segment[40..];
        input
            .send(Packet::new(fragment(&missing[8..], 8, false, 0x5566_9902)))
            .await
            .unwrap();
        input
            .send(Packet::new(fragment(&missing[..8], 0, true, 0x5566_9902)))
            .await
            .unwrap();
        let expected = [gap.as_slice(), tail.as_slice()].concat();
        let mut recovered = vec![0u8; expected.len()];
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read_exact(&mut recovered),
        )
        .await
        .expect("gap repair left TCP stream stalled")
        .expect("TCP stream read failed");
        assert_eq!(recovered, expected, "gap repair bytes xray={xray}");

        // A delayed duplicate of the previously SACKed segment cannot
        // reach the application for a second time.
        input
            .send(Packet::new(fragment(&later[8..], 8, false, 0x5566_9903)))
            .await
            .unwrap();
        input
            .send(Packet::new(fragment(&later[..8], 0, true, 0x5566_9903)))
            .await
            .unwrap();
        let mut duplicate = [0u8; 1];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(60),
                stream.read(&mut duplicate),
            )
            .await
            .is_err(),
            "duplicate SACKed segment was delivered twice, xray={xray}"
        );
        let next = b"fresh-after-sack";
        let mut next_segment = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(port, 80, 1001 + expected.len() as u32, 4096)
            .ack(server_seq)
            .write(&mut next_segment, next)
            .unwrap();
        input.send(Packet::new(next_segment)).await.unwrap();
        let mut continued = [0u8; 16];
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read_exact(&mut continued),
        )
        .await
        .expect("SACK recovery stalled subsequent payload")
        .expect("subsequent payload read failed");
        assert_eq!(&continued, next, "post-gap data xray={xray}");
    }
}

#[tokio::test]
async fn fragmented_ipv6_tcp_compound_syn_options_keep_stream_usable() {
    use etherparse::TcpOptionElement as Opt;
    use tokio::io::AsyncReadExt;

    let source = [0x31; 16];
    let destination = [0x32; 16];
    for xray in [false, true] {
        for shift in [0u8, 1, 7, 14] {
            let (stack, mut listener, _udp) = if xray {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut input, mut output) = stack.split();
            let port = 46328 + u16::from(shift);
            let mut syn_header = etherparse::TcpHeader::new(port, 80, 1000, 4096);
            syn_header.syn = true;
            syn_header
                .set_options(&[
                    Opt::MaximumSegmentSize(1280),
                    Opt::SelectiveAcknowledgementPermitted,
                    Opt::WindowScale(shift),
                    Opt::Noop,
                    Opt::Timestamp(0x1020_3040, 0),
                ])
                .unwrap();
            let mut syn = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(syn_header)
                .write(&mut syn, &[])
                .unwrap();
            let syn_payload = &syn[40..];
            assert!(syn_payload.len() > 8);
            let fragment = |body: &[u8], offset: usize, more: bool, ident: u32| {
                let ip = etherparse::Ipv6Header {
                    payload_length: (8 + body.len()) as u16,
                    next_header: etherparse::ip_number::IPV6_FRAG,
                    hop_limit: 64,
                    source,
                    destination,
                    ..Default::default()
                };
                let frag = etherparse::Ipv6FragmentHeader::new(
                    etherparse::ip_number::TCP,
                    etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                    more,
                    ident,
                );
                [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), body].concat()
            };
            // The options start after the *first* IPv6 fragment. Reassemble
            // an out-of-order 40-byte SYN with MSS/SACK/WS/Timestamp intact.
            input
                .send(Packet::new(fragment(
                    &syn_payload[8..],
                    8,
                    false,
                    0x5566_8800 + u32::from(shift),
                )))
                .await
                .unwrap();
            input
                .send(Packet::new(fragment(
                    &syn_payload[..8],
                    0,
                    true,
                    0x5566_8800 + u32::from(shift),
                )))
                .await
                .unwrap();
            let syn_ack = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                output.next(),
            )
            .await
            .expect("missing compound-SYN response")
            .expect("outbound stack closed")
            .expect("outbound stack error");
            let (server_seq, server_ts) =
                match etherparse::SlicedPacket::from_ip(syn_ack.data())
                    .expect("invalid compound-SYN response")
                    .transport
                {
                    Some(etherparse::TransportSlice::Tcp(tcp)) => {
                        assert!(
                            tcp.syn() && tcp.ack() && !tcp.rst(),
                            "compound SYN rejected: xray={xray}, shift={shift}"
                        );
                        let options: Vec<_> = tcp.options_iterator().collect();
                        assert!(
                            options
                                .iter()
                                .any(|opt| matches!(opt, Ok(Opt::WindowScale(_)))),
                            "missing scaled SYN-ACK: xray={xray}, shift={shift}"
                        );
                        assert!(
                            options.iter().any(|opt| matches!(
                                opt,
                                Ok(Opt::MaximumSegmentSize(_))
                            )),
                            "missing MSS on SYN-ACK: xray={xray}, shift={shift}"
                        );
                        assert!(
                            options.iter().any(|opt| {
                                matches!(
                                    opt,
                                    Ok(Opt::SelectiveAcknowledgementPermitted)
                                )
                            }),
                            "missing SACK on SYN-ACK: xray={xray}, shift={shift}"
                        );
                        let server_ts = options.iter().find_map(|opt| match opt {
                            Ok(Opt::Timestamp(ts, echoed)) => {
                                assert_eq!(*echoed, 0x1020_3040);
                                Some(*ts)
                            }
                            _ => None,
                        });
                        (tcp.sequence_number().wrapping_add(1), server_ts)
                    }
                    _ => panic!("compound SYN expected TCP SYN-ACK"),
                };
            let mut stream = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                listener.next(),
            )
            .await
            .expect("compound SYN not accepted")
            .expect("TCP listener ended");
            // Timestamp is optional: only echo it if the SYN-ACK actually
            // negotiated it. In particular, do not send unnegotiated TS.
            let mut data_header = etherparse::TcpHeader::new(port, 80, 1001, 4096);
            data_header.ack = true;
            data_header.acknowledgment_number = server_seq;
            if let Some(server_ts) = server_ts {
                data_header
                    .set_options(&[Opt::Timestamp(0x1020_3041, server_ts)])
                    .unwrap();
            }
            let payload = b"compound-syn-echo";
            let mut data = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp_header(data_header)
                .write(&mut data, payload)
                .unwrap();
            let tcp_payload = &data[40..];
            input
                .send(Packet::new(fragment(
                    &tcp_payload[8..],
                    8,
                    false,
                    0x5566_8900 + u32::from(shift),
                )))
                .await
                .unwrap();
            input
                .send(Packet::new(fragment(
                    &tcp_payload[..8],
                    0,
                    true,
                    0x5566_8900 + u32::from(shift),
                )))
                .await
                .unwrap();
            let mut received = [0u8; 17];
            tokio::time::timeout(
                std::time::Duration::from_millis(500),
                stream.read_exact(&mut received),
            )
            .await
            .expect("compound SYN produced a stalled stream")
            .expect("compound SYN dropped TCP data");
            assert_eq!(&received, payload, "xray={xray} shift={shift}");
        }
    }
}

#[tokio::test]
async fn active_ipv6_tcp_zero_window_defers_outbound_until_window_update() {
    use tokio::io::AsyncWriteExt;

    for (xray, scaled) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let source = [0x28; 16];
        let destination = [0x29; 16];
        let (stack, mut listener, _udp) = if xray {
            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
        } else {
            NetStack::new()
        };
        let (mut input, mut output) = stack.split();
        let mut syn = Vec::new();
        let mut syn_header = etherparse::TcpHeader::new(46326, 80, 1000, 4096);
        syn_header.syn = true;
        if scaled {
            syn_header
                .set_options(&[etherparse::TcpOptionElement::WindowScale(3)])
                .unwrap();
        }
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp_header(syn_header)
            .write(&mut syn, &[])
            .unwrap();
        input.send(Packet::new(syn)).await.unwrap();
        let syn_ack = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            output.next(),
        )
        .await
        .expect("missing zero-window SYN-ACK")
        .expect("TCP output closed")
        .expect("TCP output error");
        let server_seq = match etherparse::SlicedPacket::from_ip(syn_ack.data())
            .expect("invalid zero-window SYN-ACK")
            .transport
        {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                assert!(tcp.syn() && tcp.ack());
                if scaled {
                    assert!(
                        tcp.options().windows(2).any(|pair| pair == [3, 3]),
                        "SYN with WS=3 did not negotiate window scaling, xray={xray}"
                    );
                }
                tcp.sequence_number().wrapping_add(1)
            }
            _ => panic!("zero-window test expected SYN-ACK"),
        };
        let mut server_stream = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            listener.next(),
        )
        .await
        .expect("zero-window stream missing")
        .expect("TCP listener closed");
        let mut zero_ack = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(46326, 80, 1001, 0)
            .ack(server_seq)
            .write(&mut zero_ack, &[])
            .unwrap();
        input.send(Packet::new(zero_ack.clone())).await.unwrap();
        // Let smoltcp apply the window advertisement before the app writes.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let message = b"buffer-until-window-reopens";
        tokio::time::timeout(
            std::time::Duration::from_millis(400),
            server_stream.write_all(message),
        )
        .await
        .expect("server stream stalled while buffering")
        .expect("server failed to buffer for zero-window peer");
        // A zero-window probe is at most one byte. The entire application
        // message must not be emitted with the peer's window closed.
        if let Ok(Some(Ok(frame))) =
            tokio::time::timeout(std::time::Duration::from_millis(90), output.next())
                .await
            && let Some(etherparse::TransportSlice::Tcp(tcp)) =
                etherparse::SlicedPacket::from_ip(frame.data())
                    .ok()
                    .and_then(|p| p.transport)
        {
            assert!(
                tcp.payload().len() <= 1,
                "netstack emitted application data before window update, xray={xray}"
            );
        }

        let mut open_ack = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(46326, 80, 1001, 4096)
            .ack(server_seq)
            .write(&mut open_ack, &[])
            .unwrap();
        let tcp = &open_ack[40..];
        let fragment = |body: &[u8], offset: usize, more: bool, id: u32| {
            let ip = etherparse::Ipv6Header {
                payload_length: (8 + body.len()) as u16,
                next_header: etherparse::ip_number::IPV6_FRAG,
                hop_limit: 64,
                source,
                destination,
                ..Default::default()
            };
            let frag = etherparse::Ipv6FragmentHeader::new(
                etherparse::ip_number::TCP,
                etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
                more,
                id,
            );
            [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), body].concat()
        };
        // The first zero->nonzero window update loses its *second IPv6
        // fragment*. The first fragment alone must never reopen the TCP
        // receive window, even though it carries a valid TCP port/seq tuple.
        input
            .send(Packet::new(fragment(&tcp[..8], 0, true, 0x5566_7721)))
            .await
            .unwrap();
        // Keep the window closed for multiple persist-timer cycles while
        // the incomplete fragmented update is pending. On one-byte probes,
        // reply with an ACK still advertising a *zero* window.
        let mut observed_probes = 0;
        let blocked_until =
            tokio::time::Instant::now() + std::time::Duration::from_millis(3400);
        while tokio::time::Instant::now() < blocked_until {
            let remaining =
                blocked_until.saturating_duration_since(tokio::time::Instant::now());
            let Ok(Some(Ok(frame))) =
                tokio::time::timeout(remaining, output.next()).await
            else {
                break;
            };
            if let Some(etherparse::TransportSlice::Tcp(reply)) =
                etherparse::SlicedPacket::from_ip(frame.data())
                    .ok()
                    .and_then(|p| p.transport)
            {
                assert!(
                    reply.payload().len() <= 1,
                    "incomplete IPv6 window update released full TCP payload, xray={xray}"
                );
                if !reply.payload().is_empty() {
                    observed_probes += 1;
                    input.send(Packet::new(zero_ack.clone())).await.unwrap();
                }
            }
        }
        assert!(
            observed_probes >= 1,
            "zero-window probe was not retransmitted while an update fragment was missing, xray={xray}"
        );
        // With WS=3, the peer advertises only 8 receive bytes when the
        // on-wire window field becomes one. Verify the actual send bound
        // before announcing the full receive window.
        let mut received = Vec::new();
        if scaled {
            let mut tiny_update = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp(46326, 80, 1001, 1)
                .ack(server_seq)
                .write(&mut tiny_update, &[])
                .unwrap();
            input.send(Packet::new(tiny_update)).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_millis(650), async {
                while received.len() < 8 {
                    let frame = output
                        .next()
                        .await
                        .expect("narrow-window output ended")
                        .unwrap();
                    if let Some(etherparse::TransportSlice::Tcp(tcp)) =
                        etherparse::SlicedPacket::from_ip(frame.data())
                            .ok()
                            .and_then(|packet| packet.transport)
                        && tcp.sequence_number()
                            == server_seq + received.len() as u32
                        && !tcp.payload().is_empty()
                    {
                        received.extend_from_slice(tcp.payload());
                    }
                    assert!(
                        received.len() <= 8,
                        "WS=3 advertised window 1 exceeded eight bytes, xray={xray}"
                    );
                }
            })
            .await
            .expect("WS=3 eight-byte window did not release any TCP data");
            // Advertise zero again while acknowledging exactly those eight
            // bytes, then reopen the full window with a new fragment ID.
            let mut closed_again = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp(46326, 80, 1001, 0)
                .ack(server_seq + received.len() as u32)
                .write(&mut closed_again, &[])
                .unwrap();
            input.send(Packet::new(closed_again)).await.unwrap();
        }
        let mut completed_update = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(46326, 80, 1001, 4096)
            .ack(server_seq + received.len() as u32)
            .write(&mut completed_update, &[])
            .unwrap();
        let completed_tcp = &completed_update[40..];
        // Resend the entire window update with a fresh fragment ID, in
        // reverse fragment arrival order, rather than completing the lost ID.
        input
            .send(Packet::new(fragment(
                &completed_tcp[8..],
                8,
                false,
                0x5566_7722,
            )))
            .await
            .unwrap();
        input
            .send(Packet::new(fragment(
                &completed_tcp[..8],
                0,
                true,
                0x5566_7722,
            )))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(1200), async {
            while let Some(Ok(frame)) = output.next().await {
                let Ok(sliced) = etherparse::SlicedPacket::from_ip(frame.data())
                else {
                    continue;
                };
                let Some(etherparse::TransportSlice::Tcp(tcp)) = sliced.transport
                else {
                    continue;
                };
                if tcp.rst() {
                    panic!("zero-window update reset TCP stream, xray={xray}");
                }
                if !tcp.payload().is_empty()
                    && tcp.sequence_number() == server_seq + received.len() as u32
                {
                    received.extend_from_slice(tcp.payload());
                    if received.len() >= message.len() {
                        break;
                    }
                }
            }
        })
        .await
        .expect("outbound data did not recover after window update");
        assert_eq!(received, message, "post-window update echo, xray={xray}");
    }
}

#[tokio::test]
async fn active_ipv6_tcp_future_ack_challenges_but_preserves_stream_data() {
    use tokio::io::AsyncReadExt;

    let source = [0x24; 16];
    let destination = [0x25; 16];
    for xray in [false, true] {
        let (stack, mut listener, _udp) = if xray {
            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
        } else {
            NetStack::new()
        };
        let (mut input, mut output) = stack.split();
        let mut syn = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(46324, 80, 1000, 65535)
            .syn()
            .write(&mut syn, &[])
            .unwrap();
        input.send(Packet::new(syn)).await.unwrap();
        let syn_ack = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            output.next(),
        )
        .await
        .expect("missing initial SYN-ACK")
        .expect("output closed")
        .expect("output failed");
        let server_seq = match etherparse::SlicedPacket::from_ip(syn_ack.data())
            .expect("invalid SYN-ACK")
            .transport
        {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                assert!(tcp.syn() && tcp.ack());
                tcp.sequence_number().wrapping_add(1)
            }
            _ => panic!("expected SYN-ACK"),
        };
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            listener.next(),
        )
        .await
        .expect("TCP accept missing")
        .expect("listener closed");

        let mut normal_ack = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(46324, 80, 1001, 65535)
            .ack(server_seq)
            .write(&mut normal_ack, &[])
            .unwrap();
        input.send(Packet::new(normal_ack)).await.unwrap();

        // smoltcp (both netstack constructors) challenges an ACK number
        // beyond SND.NXT; pinned Xray gVisor silently drops the same live
        // probe. Document the difference, and pin stream safety locally.
        let mut impossible_ack = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(46324, 80, 1001, 65535)
            .ack(server_seq.wrapping_add(64))
            .write(&mut impossible_ack, &[])
            .unwrap();
        input.send(Packet::new(impossible_ack)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(400), async {
            while let Some(Ok(frame)) = output.next().await {
                if let Some(etherparse::TransportSlice::Tcp(tcp)) =
                    etherparse::SlicedPacket::from_ip(frame.data())
                        .ok()
                        .and_then(|packet| packet.transport)
                    && tcp.ack()
                    && !tcp.syn()
                    && !tcp.rst()
                    && tcp.acknowledgment_number() == 1001
                {
                    return;
                }
            }
            panic!("TCP output ended before challenge ACK");
        })
        .await
        .expect("future ACK did not produce a TCP challenge ACK");

        let payload = b"still-open";
        let mut data = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(46324, 80, 1001, 65535)
            .ack(server_seq)
            .write(&mut data, payload)
            .unwrap();
        input.send(Packet::new(data)).await.unwrap();
        let mut received = [0u8; 10];
        tokio::time::timeout(
            std::time::Duration::from_millis(400),
            stream.read_exact(&mut received),
        )
        .await
        .expect("future ACK stalled subsequent data")
        .expect("stream read failed after future ACK");
        assert_eq!(&received, payload);
    }
}

#[tokio::test]
async fn fragmented_ipv6_active_tcp_rst_malformed_options_allow_xray_tuple_reuse() {
    use tokio::io::AsyncReadExt;

    let source = [0x20; 16];
    let destination = [0x21; 16];
    for chained in [false, true] {
        for first_tcp in [8usize, 24] {
            for &(name, option, malformed, rst_flags) in &[
                ("nop", [1u8, 1, 1, 1], false, 0x14u8),
                ("bad-mss", [2, 0, 5, 180], true, 0x14),
                ("bad-unknown", [30, 0, 1, 1], true, 0x14),
                ("bare-nop", [1, 1, 1, 1], false, 0x04),
                ("bare-bad-mss", [2, 0, 5, 180], true, 0x04),
                ("bare-bad-unknown", [30, 0, 1, 1], true, 0x04),
            ] {
                for xray in [false, true] {
                    let (stack, mut listener, _udp) = if xray {
                        NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
                    } else {
                        NetStack::new()
                    };
                    let (mut input, mut output) = stack.split();
                    let mut syn = Vec::new();
                    etherparse::PacketBuilder::ipv6(source, destination, 64)
                        .tcp(46322, 80, 1000, 65535)
                        .syn()
                        .write(&mut syn, &[])
                        .unwrap();
                    input.send(Packet::new(syn)).await.unwrap();
                    let first_syn_ack = tokio::time::timeout(
                        std::time::Duration::from_millis(350),
                        output.next(),
                    )
                    .await
                    .expect("initial SYN-ACK timed out")
                    .expect("stack output ended")
                    .expect("stack packet failed");
                    let first_server_seq = match etherparse::SlicedPacket::from_ip(
                        first_syn_ack.data(),
                    )
                    .unwrap()
                    .transport
                    {
                        Some(etherparse::TransportSlice::Tcp(tcp)) => {
                            assert!(tcp.syn() && tcp.ack());
                            tcp.sequence_number()
                        }
                        _ => panic!("initial SYN must receive SYN-ACK"),
                    };
                    let mut held_stream = tokio::time::timeout(
                        std::time::Duration::from_millis(350),
                        listener.next(),
                    )
                    .await
                    .expect("initial stream missing")
                    .expect("listener closed");
                    let mut ack = Vec::new();
                    etherparse::PacketBuilder::ipv6(source, destination, 64)
                        .tcp(46322, 80, 1001, 65535)
                        .ack(first_server_seq.wrapping_add(1))
                        .write(&mut ack, &[])
                        .unwrap();
                    input.send(Packet::new(ack)).await.unwrap();

                    let mut tcp = vec![0u8; 20];
                    tcp[0..2].copy_from_slice(&46322u16.to_be_bytes());
                    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
                    let live_marker = b"still-open";
                    let established_seq = 1001u32 + live_marker.len() as u32;
                    tcp[4..8].copy_from_slice(&established_seq.to_be_bytes());
                    tcp[8..12].copy_from_slice(
                        &first_server_seq.wrapping_add(1).to_be_bytes(),
                    );
                    tcp[12] = 6 << 4;
                    tcp[13] = rst_flags; // RST+ACK or bare RST
                    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
                    tcp.extend_from_slice(&option);
                    tcp.extend_from_slice(b"rst-body"); // ensure nonempty final fragment
                    let mut pseudo = Vec::new();
                    pseudo.extend_from_slice(&source);
                    pseudo.extend_from_slice(&destination);
                    pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
                    pseudo.extend_from_slice(&[
                        0,
                        0,
                        0,
                        etherparse::ip_number::TCP.0,
                    ]);
                    pseudo.extend_from_slice(&tcp);
                    tcp[16..18]
                        .copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());

                    let mut data = vec![
                        if chained {
                            etherparse::ip_number::IPV6_DEST_OPTIONS.0
                        } else {
                            etherparse::ip_number::TCP.0
                        },
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                    ];
                    if chained {
                        data.extend_from_slice(&[
                            etherparse::ip_number::TCP.0,
                            0,
                            1,
                            4,
                            0,
                            0,
                            0,
                            0,
                        ]);
                    }
                    let split = data.len() + first_tcp;
                    let options_len = data.len();
                    data.extend_from_slice(&tcp);

                    // A far-out-of-window RST cannot tear down the active
                    // connection. Test both the TCP parser and sequence guard
                    // before sending an in-window RST on the same tuple.
                    let mut far_tcp = tcp.clone();
                    far_tcp[4..8].copy_from_slice(
                        &established_seq.wrapping_add(1 << 20).to_be_bytes(),
                    );
                    far_tcp[16..18].fill(0);
                    let mut far_sum = pseudo[..40].to_vec();
                    far_sum.extend_from_slice(&far_tcp);
                    far_tcp[16..18]
                        .copy_from_slice(&internet_checksum(&far_sum).to_be_bytes());
                    let mut far_data = data.clone();
                    far_data[options_len..].copy_from_slice(&far_tcp);
                    let fragment = |body: &[u8], at: usize, more: bool| {
                        let ip = etherparse::Ipv6Header {
                            payload_length: (8 + body.len()) as u16,
                            next_header: etherparse::ip_number::IPV6_FRAG,
                            hop_limit: 64,
                            source,
                            destination,
                            ..Default::default()
                        };
                        let fh = etherparse::Ipv6FragmentHeader::new(
                            etherparse::ip_number::IPV6_DEST_OPTIONS,
                            etherparse::IpFragOffset::try_new((at / 8) as u16)
                                .unwrap(),
                            more,
                            0x7788_99b6,
                        );
                        [ip.to_bytes().as_slice(), fh.to_bytes().as_slice(), body]
                            .concat()
                    };
                    input
                        .send(Packet::new(fragment(
                            &far_data[split..],
                            split,
                            false,
                        )))
                        .await
                        .unwrap();
                    input
                        .send(Packet::new(fragment(&far_data[..split], 0, true)))
                        .await
                        .unwrap();
                    if xray {
                        // The RST has a nonempty trailing payload, but gVisor
                        // tests RST window membership at length zero. At
                        // RCV.NXT-1 it must not terminate the established flow.
                        // smoltcp without this compatibility guard would
                        // count the payload as overlap with the receive window.
                        let mut behind_tcp = tcp.clone();
                        behind_tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
                        behind_tcp[16..18].fill(0);
                        let mut behind_sum = pseudo[..40].to_vec();
                        behind_sum.extend_from_slice(&behind_tcp);
                        behind_tcp[16..18].copy_from_slice(
                            &internet_checksum(&behind_sum).to_be_bytes(),
                        );
                        let mut behind_data = data.clone();
                        behind_data[options_len..].copy_from_slice(&behind_tcp);
                        input
                            .send(Packet::new(fragment(
                                &behind_data[split..],
                                split,
                                false,
                            )))
                            .await
                            .unwrap();
                        input
                            .send(Packet::new(fragment(
                                &behind_data[..split],
                                0,
                                true,
                            )))
                            .await
                            .unwrap();
                    }
                    if xray {
                        // An exact-window RST would terminate the connection
                        // if its original checksum were accepted. Corrupt the
                        // trailing byte after computing TCP checksum and prove
                        // that compatibility normalization cannot bypass it.
                        let mut corrupt_data = data.clone();
                        *corrupt_data.last_mut().unwrap() ^= 0x01;
                        input
                            .send(Packet::new(fragment(
                                &corrupt_data[split..],
                                split,
                                false,
                            )))
                            .await
                            .unwrap();
                        input
                            .send(Packet::new(fragment(
                                &corrupt_data[..split],
                                0,
                                true,
                            )))
                            .await
                            .unwrap();
                    }
                    let mut still_open = Vec::new();
                    etherparse::PacketBuilder::ipv6(source, destination, 64)
                        .tcp(46322, 80, 1001, 65535)
                        .ack(first_server_seq.wrapping_add(1))
                        .write(&mut still_open, live_marker)
                        .unwrap();
                    input.send(Packet::new(still_open)).await.unwrap();
                    let mut observed = [0u8; 10];
                    tokio::time::timeout(
                        std::time::Duration::from_millis(280),
                        held_stream.read_exact(&mut observed),
                    )
                    .await
                    .expect("out-of-window RST closed the active stream")
                    .expect("live data read failed");
                    assert_eq!(&observed, live_marker);

                    input
                        .send(Packet::new(fragment(&data[split..], split, false)))
                        .await
                        .unwrap();
                    input
                        .send(Packet::new(fragment(&data[..split], 0, true)))
                        .await
                        .unwrap();

                    let mut next_syn = Vec::new();
                    etherparse::PacketBuilder::ipv6(source, destination, 64)
                        .tcp(46322, 80, 3000, 65535)
                        .syn()
                        .write(&mut next_syn, &[])
                        .unwrap();
                    // Wait for the packet pump and smoltcp to process RST
                    // before presenting a new SYN for the same four-tuple.
                    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                    input.send(Packet::new(next_syn)).await.unwrap();
                    let accepted = tokio::time::timeout(
                        std::time::Duration::from_millis(180),
                        async {
                            while let Some(Ok(packet)) = output.next().await {
                                if let Some(etherparse::TransportSlice::Tcp(tcp)) =
                                    etherparse::SlicedPacket::from_ip(packet.data())
                                        .ok()
                                        .and_then(|p| p.transport)
                                    && tcp.syn()
                                    && tcp.ack()
                                    && tcp.acknowledgment_number() == 3001
                                {
                                    return true;
                                }
                            }
                            false
                        },
                    )
                    .await
                    .unwrap_or(false);
                    assert_eq!(
                        accepted,
                        xray || !malformed,
                        "{name}: tuple reuse mismatch flags={rst_flags:#x}, chained={chained}, first={first_tcp}, xray={xray}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_active_tcp_malformed_ack_and_fin_reach_stream_in_xray_mode()
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let source = [0x20; 16];
    let destination = [0x21; 16];

    for chained in [false, true] {
        for xray in [false, true] {
            let (stack, mut tcp_listener, _udp) = if xray {
                NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
            } else {
                NetStack::new()
            };
            let (mut sink, mut output) = stack.split();
            let mut syn = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp(46321, 80, 1000, 65535)
                .syn()
                .write(&mut syn, &[])
                .unwrap();
            sink.send(Packet::new(syn)).await.unwrap();
            let syn_ack = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                output.next(),
            )
            .await
            .expect("missing SYN-ACK")
            .expect("output ended")
            .expect("output failed");
            let server_seq = match etherparse::SlicedPacket::from_ip(syn_ack.data())
                .expect("invalid SYN-ACK packet")
                .transport
            {
                Some(etherparse::TransportSlice::Tcp(tcp)) => {
                    assert!(tcp.syn() && tcp.ack());
                    tcp.sequence_number()
                }
                _ => panic!("expected TCP SYN-ACK"),
            };
            let mut stream = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                tcp_listener.next(),
            )
            .await
            .expect("new TCP stream timed out")
            .expect("TCP listener closed");
            let mut handshake_ack = Vec::new();
            etherparse::PacketBuilder::ipv6(source, destination, 64)
                .tcp(46321, 80, 1001, 65535)
                .ack(server_seq.wrapping_add(1))
                .write(&mut handshake_ack, &[])
                .unwrap();
            sink.send(Packet::new(handshake_ack)).await.unwrap();

            let tcp_bytes = |seq: u32, flags: u8, options: [u8; 4], data: &[u8]| {
                let mut tcp = vec![0u8; 20];
                tcp[0..2].copy_from_slice(&46321u16.to_be_bytes());
                tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
                tcp[4..8].copy_from_slice(&seq.to_be_bytes());
                tcp[8..12]
                    .copy_from_slice(&server_seq.wrapping_add(1).to_be_bytes());
                tcp[12] = 6 << 4;
                tcp[13] = flags;
                tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
                tcp.extend_from_slice(&options);
                tcp.extend_from_slice(data);
                let mut pseudo = Vec::new();
                pseudo.extend_from_slice(&source);
                pseudo.extend_from_slice(&destination);
                pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, etherparse::ip_number::TCP.0]);
                pseudo.extend_from_slice(&tcp);
                tcp[16..18]
                    .copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
                tcp
            };

            let send_fragmented = |tcp: Vec<u8>, id: u32| {
                let mut fragmentable = vec![
                    if chained {
                        etherparse::ip_number::IPV6_DEST_OPTIONS.0
                    } else {
                        etherparse::ip_number::TCP.0
                    },
                    0,
                    1,
                    4,
                    0,
                    0,
                    0,
                    0,
                ];
                if chained {
                    fragmentable.extend_from_slice(&[
                        etherparse::ip_number::TCP.0,
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                    ]);
                }
                let split = fragmentable.len() + 8;
                fragmentable.extend_from_slice(&tcp);
                let fragment = |body: &[u8], offset: usize, more: bool| {
                    let ipv6 = etherparse::Ipv6Header {
                        payload_length: (8 + body.len()) as u16,
                        next_header: etherparse::ip_number::IPV6_FRAG,
                        hop_limit: 64,
                        source,
                        destination,
                        ..Default::default()
                    };
                    let frag = etherparse::Ipv6FragmentHeader::new(
                        etherparse::ip_number::IPV6_DEST_OPTIONS,
                        etherparse::IpFragOffset::try_new((offset / 8) as u16)
                            .unwrap(),
                        more,
                        id,
                    );
                    [ipv6.to_bytes().as_slice(), frag.to_bytes().as_slice(), body]
                        .concat()
                };
                [
                    fragment(&fragmentable[..split], 0, true),
                    fragment(&fragmentable[split..], split, false),
                ]
            };

            let marker = b"active-data";
            let invalid_options = [2, 0, 5, 180];
            let valid_options = [1, 1, 1, 1];
            let packet = send_fragmented(
                tcp_bytes(1001, 0x10, invalid_options, marker),
                0x7788_99b3,
            );
            if xray {
                let mut corrupted_tail = packet[1].clone();
                let last = corrupted_tail.len() - 1;
                corrupted_tail[last] ^= 1;
                sink.send(Packet::new(corrupted_tail)).await.unwrap();
                sink.send(Packet::new(packet[0].clone())).await.unwrap();
                let mut rejected = [0u8; 1];
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(70),
                        stream.read(&mut rejected),
                    )
                    .await
                    .is_err(),
                    "bad original TCP checksum must not be normalized for active ACK"
                );
            }
            // Reuse the fragment ID after checksum failure; the valid
            // retransmission must progress on the same established stream.
            sink.send(Packet::new(packet[1].clone())).await.unwrap();
            sink.send(Packet::new(packet[0].clone())).await.unwrap();

            if !xray {
                let mut unexpected = [0u8; 1];
                assert!(
                    tokio::time::timeout(
                        std::time::Duration::from_millis(70),
                        stream.read(&mut unexpected)
                    )
                    .await
                    .is_err(),
                    "default netstack must keep rejecting malformed active ACK options"
                );
                // A valid retransmission at the same sequence must succeed.
                let packet = send_fragmented(
                    tcp_bytes(1001, 0x10, valid_options, marker),
                    0x7788_99b4,
                );
                sink.send(Packet::new(packet[1].clone())).await.unwrap();
                sink.send(Packet::new(packet[0].clone())).await.unwrap();
            }
            let mut received = [0u8; 11];
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                stream.read_exact(&mut received),
            )
            .await
            .expect("active TCP ACK data did not reach the stream")
            .expect("TCP stream read failed");
            assert_eq!(&received, marker);

            let fin_options = if xray { invalid_options } else { valid_options };
            let fin_tail = b"fin-tail";
            let packet = send_fragmented(
                tcp_bytes(1001 + marker.len() as u32, 0x11, fin_options, fin_tail),
                0x7788_99b5,
            );
            sink.send(Packet::new(packet[1].clone())).await.unwrap();
            sink.send(Packet::new(packet[0].clone())).await.unwrap();
            let mut received = [0u8; 8];
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                stream.read_exact(&mut received),
            )
            .await
            .expect("active TCP FIN tail did not reach stream")
            .expect("TCP FIN-tail read failed");
            assert_eq!(&received, fin_tail);
            let mut after_fin = [0u8; 1];
            let n = tokio::time::timeout(
                std::time::Duration::from_millis(300),
                stream.read(&mut after_fin),
            )
            .await
            .expect("active TCP FIN did not close its receive half")
            .expect("TCP FIN read failed");
            assert_eq!(n, 0, "active TCP FIN must expose EOF");

            // Peer FIN closes only the receive half: application-side sends
            // must still work until the application shuts down its own half.
            let reverse_data = b"after-peer-fin";
            tokio::time::timeout(
                std::time::Duration::from_millis(300),
                stream.write_all(reverse_data),
            )
            .await
            .expect("send after peer FIN stalled")
            .expect("send after peer FIN failed");
            tokio::time::timeout(std::time::Duration::from_millis(400), async {
                while let Some(Ok(packet)) = output.next().await {
                    if let Some(etherparse::TransportSlice::Tcp(tcp)) =
                        etherparse::SlicedPacket::from_ip(packet.data())
                            .ok()
                            .and_then(|sliced| sliced.transport)
                        && tcp.payload() == reverse_data
                    {
                        assert!(
                            !tcp.rst() && !tcp.fin(),
                            "send half must remain usable after peer FIN"
                        );
                        return;
                    }
                }
                panic!("TCP output stream ended before reverse data");
            })
            .await
            .expect("TCP data after peer FIN not emitted");
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_tcp_non_syn_malformed_options_match_xray_rst() {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let option_cases = [
        ("nop", [1u8, 1, 1, 1], false),
        ("bad-mss", [2, 0, 5, 180], true),
        ("bad-unknown", [30, 0, 1, 1], true),
    ];

    for chained in [false, true] {
        for first_tcp_bytes in [8usize, 24] {
            for (name, flags) in [("ack", 0x10u8), ("fin-ack", 0x11), ("rst", 0x04)]
            {
                for &(option_name, options, is_invalid) in &option_cases {
                    let mut tcp = vec![0u8; 20];
                    tcp[0..2].copy_from_slice(&46123u16.to_be_bytes());
                    tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
                    tcp[4..8].copy_from_slice(&0x529d_4321u32.to_be_bytes());
                    let acknowledgement = 0x529e_9876u32;
                    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
                    tcp[12] = 6 << 4;
                    tcp[13] = flags;
                    tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
                    tcp.extend_from_slice(&options);
                    tcp.extend_from_slice(b"non-syn-options");
                    let mut pseudo = Vec::new();
                    pseudo.extend_from_slice(&source);
                    pseudo.extend_from_slice(&destination);
                    pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
                    pseudo.extend_from_slice(&[
                        0,
                        0,
                        0,
                        etherparse::ip_number::TCP.0,
                    ]);
                    pseudo.extend_from_slice(&tcp);
                    tcp[16..18]
                        .copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
                    pseudo.truncate(pseudo.len() - tcp.len());
                    pseudo.extend_from_slice(&tcp);
                    assert_eq!(internet_checksum(&pseudo), 0);

                    let mut data = vec![
                        if chained {
                            etherparse::ip_number::IPV6_DEST_OPTIONS.0
                        } else {
                            etherparse::ip_number::TCP.0
                        },
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                    ];
                    if chained {
                        data.extend_from_slice(&[
                            etherparse::ip_number::TCP.0,
                            0,
                            1,
                            4,
                            0,
                            0,
                            0,
                            0,
                        ]);
                    }
                    let split = data.len() + first_tcp_bytes;
                    data.extend_from_slice(&tcp);
                    let fragment = |body: &[u8], offset: usize, more: bool| {
                        let ipv6 = etherparse::Ipv6Header {
                            payload_length: (8 + body.len()) as u16,
                            next_header: etherparse::ip_number::IPV6_FRAG,
                            hop_limit: 64,
                            source,
                            destination,
                            ..Default::default()
                        };
                        let frag = etherparse::Ipv6FragmentHeader::new(
                            etherparse::ip_number::IPV6_DEST_OPTIONS,
                            etherparse::IpFragOffset::try_new((offset / 8) as u16)
                                .unwrap(),
                            more,
                            0x7788_99b2,
                        );
                        [
                            ipv6.to_bytes().as_slice(),
                            frag.to_bytes().as_slice(),
                            body,
                        ]
                        .concat()
                    };
                    let first = fragment(&data[..split], 0, true);
                    let second = fragment(&data[split..], split, false);
                    for xray in [false, true] {
                        let (stack, _tcp, _udp) = if xray {
                            NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
                        } else {
                            NetStack::new()
                        };
                        let (mut sink, mut output) = stack.split();
                        sink.send(Packet::new(second.clone())).await.unwrap();
                        sink.send(Packet::new(first.clone())).await.unwrap();

                        let expect_rst = flags != 0x04 && (xray || !is_invalid);
                        if expect_rst {
                            let packet = tokio::time::timeout(
                                std::time::Duration::from_millis(300),
                                output.next(),
                            )
                            .await
                            .expect("missing TCP RST for unmatched ACK or FIN-ACK")
                            .expect("TCP output channel closed")
                            .expect("TCP output failed");
                            let reply =
                                etherparse::SlicedPacket::from_ip(packet.data())
                                    .expect("invalid TCP response");
                            let Some(etherparse::TransportSlice::Tcp(tcp)) =
                                reply.transport
                            else {
                                panic!("expected TCP RST response");
                            };
                            assert!(tcp.rst() && !tcp.ack(), "expected bare RST");
                            assert_eq!(tcp.sequence_number(), acknowledgement);
                        } else {
                            assert!(
                                tokio::time::timeout(
                                    std::time::Duration::from_millis(50),
                                    output.next(),
                                )
                                .await
                                .is_err(),
                                "unexpected non-SYN reply {name}/{option_name}, chained={chained}, xray={xray}"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_tcp_data_offset_boundaries_match_pinned_xray() {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let offset_words = [0u8, 4, 5, 6, 15];

    for chained in [false, true] {
        for first_tcp_bytes in [8usize, 24] {
            for &offset in &offset_words {
                let mut unmodified = Vec::new();
                etherparse::PacketBuilder::ipv6(source, destination, 64)
                    .tcp(47123, 80, 0, 65535)
                    .syn()
                    .write(&mut unmodified, b"offset-case")
                    .unwrap();

                let mut tcp = unmodified[40..60].to_vec();
                tcp[12] = offset << 4;
                tcp.extend_from_slice(&[1, 1, 1, 1]); // valid NOPs for offset 6
                tcp.extend_from_slice(&unmodified[60..]);
                tcp[16..18].fill(0);
                let mut pseudo = Vec::new();
                pseudo.extend_from_slice(&source);
                pseudo.extend_from_slice(&destination);
                pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, etherparse::ip_number::TCP.0]);
                pseudo.extend_from_slice(&tcp);
                tcp[16..18]
                    .copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
                pseudo.truncate(pseudo.len() - tcp.len());
                pseudo.extend_from_slice(&tcp);
                assert_eq!(internet_checksum(&pseudo), 0);

                let mut data = vec![
                    if chained {
                        etherparse::ip_number::IPV6_DEST_OPTIONS.0
                    } else {
                        etherparse::ip_number::TCP.0
                    },
                    0,
                    1,
                    4,
                    0,
                    0,
                    0,
                    0,
                ];
                if chained {
                    data.extend_from_slice(&[
                        etherparse::ip_number::TCP.0,
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                    ]);
                }
                let split = data.len() + first_tcp_bytes;
                data.extend_from_slice(&tcp);
                let fragment = |body: &[u8], at: usize, more: bool| {
                    let header = etherparse::Ipv6Header {
                        payload_length: (8 + body.len()) as u16,
                        next_header: etherparse::ip_number::IPV6_FRAG,
                        hop_limit: 64,
                        source,
                        destination,
                        ..Default::default()
                    };
                    let fragment_header = etherparse::Ipv6FragmentHeader::new(
                        etherparse::ip_number::IPV6_DEST_OPTIONS,
                        etherparse::IpFragOffset::try_new((at / 8) as u16).unwrap(),
                        more,
                        0x7788_99b1,
                    );
                    [
                        header.to_bytes().as_slice(),
                        fragment_header.to_bytes().as_slice(),
                        body,
                    ]
                    .concat()
                };
                let first = fragment(&data[..split], 0, true);
                let second = fragment(&data[split..], split, false);

                for xray in [false, true] {
                    let (stack, _tcp, _udp) = if xray {
                        NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
                    } else {
                        NetStack::new()
                    };
                    let (mut sink, mut output) = stack.split();
                    sink.send(Packet::new(second.clone())).await.unwrap();
                    sink.send(Packet::new(first.clone())).await.unwrap();

                    if matches!(offset, 5 | 6) {
                        let response = tokio::time::timeout(
                            std::time::Duration::from_millis(300),
                            output.next(),
                        )
                        .await
                        .expect("valid data offset must produce a SYN-ACK")
                        .expect("stack output closed")
                        .expect("stack output error");
                        assert!(
                            is_any_ip_syn_ack(response.data()),
                            "offset={offset}, chained={chained}, tcp-first={first_tcp_bytes}, xray={xray}"
                        );
                    } else {
                        assert!(
                            tokio::time::timeout(
                                std::time::Duration::from_millis(60),
                                output.next(),
                            )
                            .await
                            .is_err(),
                            "invalid offset={offset} must be rejected, chained={chained}, tcp-first={first_tcp_bytes}, xray={xray}"
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_tcp_malformed_syn_options_follow_xray_without_bypassing_checksum()
 {
    let source = [0x20; 16];
    let destination = [0x21; 16];
    let option_cases: [(&str, [u8; 4], bool); 8] = [
        ("valid-mss", [2, 4, 5, 180], false),
        ("mss-zero", [2, 0, 5, 180], true),
        ("mss-short", [2, 3, 5, 180], true),
        ("mss-overrun", [2, 5, 5, 180], true),
        ("window-scale-short", [3, 2, 7, 1], true),
        ("timestamp-short", [8, 2, 1, 1], false),
        ("unknown-zero", [30, 0, 1, 1], true),
        ("eol-trailer", [0, 2, 0, 0], false),
    ];

    for chained in [false, true] {
        for first_tcp_bytes in [8, 24] {
            for (case_index, &(name, options, default_rejects)) in
                option_cases.iter().enumerate()
            {
                let port = 46000 + u16::try_from(case_index).unwrap();
                let mut full = Vec::new();
                etherparse::PacketBuilder::ipv6(source, destination, 64)
                    .tcp(port, 80, 0, 65535)
                    .syn()
                    .write(&mut full, b"option-case")
                    .unwrap();
                let mut tcp = full[40..60].to_vec();
                tcp[12] = 6 << 4;
                tcp.extend_from_slice(&options);
                tcp.extend_from_slice(&full[60..]);
                tcp[16..18].fill(0);
                let mut pseudo = Vec::new();
                pseudo.extend_from_slice(&source);
                pseudo.extend_from_slice(&destination);
                pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, etherparse::ip_number::TCP.0]);
                pseudo.extend_from_slice(&tcp);
                let checksum = internet_checksum(&pseudo);
                tcp[16..18].copy_from_slice(&checksum.to_be_bytes());

                let mut fragmentable = vec![
                    if chained {
                        etherparse::ip_number::IPV6_DEST_OPTIONS.0
                    } else {
                        etherparse::ip_number::TCP.0
                    },
                    0,
                    1,
                    4,
                    0,
                    0,
                    0,
                    0,
                ];
                if chained {
                    fragmentable.extend_from_slice(&[
                        etherparse::ip_number::TCP.0,
                        0,
                        1,
                        4,
                        0,
                        0,
                        0,
                        0,
                    ]);
                }
                let split = fragmentable.len() + first_tcp_bytes;
                fragmentable.extend_from_slice(&tcp);
                let fragment = |part: &[u8], offset: usize, more: bool| {
                    let ipv6 = etherparse::Ipv6Header {
                        payload_length: (8 + part.len()) as u16,
                        next_header: etherparse::ip_number::IPV6_FRAG,
                        hop_limit: 64,
                        source,
                        destination,
                        ..Default::default()
                    };
                    let frag = etherparse::Ipv6FragmentHeader::new(
                        etherparse::ip_number::IPV6_DEST_OPTIONS,
                        etherparse::IpFragOffset::try_new((offset / 8) as u16)
                            .unwrap(),
                        more,
                        0x7788_99b0,
                    );
                    [ipv6.to_bytes().as_slice(), frag.to_bytes().as_slice(), part]
                        .concat()
                };
                let first = fragment(&fragmentable[..split], 0, true);
                let second = fragment(&fragmentable[split..], split, false);

                let (stack, _tcp, _udp) =
                    NetStack::new_with_mtu_xray_tun_compat(1500).unwrap();
                let (mut sink, mut output) = stack.split();
                if !chained && first_tcp_bytes == 8 && name == "mss-zero" {
                    let mut invalid = fragmentable.clone();
                    let last = invalid.len() - 1;
                    invalid[last] ^= 1; // corrupt TCP checksum
                    let bad_tail = fragment(&invalid[split..], split, false);
                    sink.send(Packet::new(bad_tail)).await.unwrap();
                    sink.send(Packet::new(first.clone())).await.unwrap();
                    assert!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(60),
                            output.next()
                        )
                        .await
                        .is_err(),
                        "Xray option compatibility cannot repair a bad TCP checksum"
                    );
                }
                sink.send(Packet::new(second.clone())).await.unwrap();
                sink.send(Packet::new(first.clone())).await.unwrap();
                let response = tokio::time::timeout(
                    std::time::Duration::from_millis(300),
                    output.next(),
                )
                .await
                .expect("Xray-compatible malformed SYN options timed out")
                .expect("stack output channel closed")
                .expect("TCP packet emission failed");
                assert!(
                    is_any_ip_syn_ack(response.data()),
                    "{name}: expected SYN-ACK for first TCP bytes={first_tcp_bytes}, chained={chained}"
                );

                if default_rejects {
                    let (strict_stack, _tcp, _udp) = NetStack::new();
                    let (mut strict_sink, mut strict_output) = strict_stack.split();
                    strict_sink.send(Packet::new(second)).await.unwrap();
                    strict_sink.send(Packet::new(first)).await.unwrap();
                    assert!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(40),
                            strict_output.next()
                        )
                        .await
                        .is_err(),
                        "{name}: default mode must retain strict option handling"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_tcp_option_lengths_preserve_xray_first_fragment_boundary() {
    let source = [0x20; 16];
    let destination = [0x21; 16];

    for option_length in [0usize, 4, 20] {
        let mut unmodified = Vec::new();
        etherparse::PacketBuilder::ipv6(source, destination, 64)
            .tcp(1234, 80, 0, 65535)
            .syn()
            .write(&mut unmodified, b"tcp-option-boundary")
            .unwrap();
        let mut tcp = unmodified[40..60].to_vec();
        let mut options = Vec::new();
        if option_length > 0 {
            options.extend_from_slice(&[2, 4, 5, 180]); // MSS = 1460
            options.extend(std::iter::repeat_n(1u8, option_length - 4));
        }
        tcp[12] = ((5 + option_length / 4) as u8) << 4;
        tcp[16..18].fill(0);
        tcp.extend_from_slice(&options);
        tcp.extend_from_slice(&unmodified[60..]);
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&destination);
        pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, etherparse::ip_number::TCP.0]);
        pseudo.extend_from_slice(&tcp);
        let checksum = internet_checksum(&pseudo);
        tcp[16..18].copy_from_slice(&checksum.to_be_bytes());
        pseudo.truncate(pseudo.len() - tcp.len());
        pseudo.extend_from_slice(&tcp);
        assert_eq!(internet_checksum(&pseudo), 0, "TCP checksum must be valid");

        for chained in [false, true] {
            let mut fragmentable = vec![
                if chained {
                    etherparse::ip_number::IPV6_DEST_OPTIONS.0
                } else {
                    etherparse::ip_number::TCP.0
                },
                0,
                1,
                4,
                0,
                0,
                0,
                0,
            ];
            if chained {
                fragmentable.extend_from_slice(&[
                    etherparse::ip_number::TCP.0,
                    0,
                    1,
                    4,
                    0,
                    0,
                    0,
                    0,
                ]);
            }
            let extension_length = fragmentable.len();
            fragmentable.extend_from_slice(&tcp);

            let header_boundaries: &[usize] = if option_length == 20 {
                &[0, 8, 16, 24, 32, 40]
            } else {
                &[0, 8, 16, 24]
            };
            for &first_tcp_bytes in header_boundaries {
                let split = extension_length + first_tcp_bytes;
                let packet = |data: &[u8], offset: usize, more: bool| {
                    let ipv6 = etherparse::Ipv6Header {
                        payload_length: (8 + data.len()) as u16,
                        next_header: etherparse::ip_number::IPV6_FRAG,
                        hop_limit: 64,
                        source,
                        destination,
                        ..Default::default()
                    };
                    let fragment = etherparse::Ipv6FragmentHeader::new(
                        etherparse::ip_number::IPV6_DEST_OPTIONS,
                        etherparse::IpFragOffset::try_new((offset / 8) as u16)
                            .unwrap(),
                        more,
                        0x7788_99af,
                    );
                    [
                        ipv6.to_bytes().as_slice(),
                        fragment.to_bytes().as_slice(),
                        data,
                    ]
                    .concat()
                };
                let first = packet(&fragmentable[..split], 0, true);
                let second = packet(&fragmentable[split..], split, false);

                for xray_mode in [false, true] {
                    let (stack, _tcp, _udp) = if xray_mode {
                        NetStack::new_with_mtu_xray_tun_compat(1500).unwrap()
                    } else {
                        NetStack::new()
                    };
                    let (mut sink, mut output) = stack.split();
                    sink.send(Packet::new(second.clone())).await.unwrap();
                    sink.send(Packet::new(first.clone())).await.unwrap();

                    if xray_mode && first_tcp_bytes == 0 {
                        assert!(
                            tokio::time::timeout(
                                std::time::Duration::from_millis(60),
                                output.next()
                            )
                            .await
                            .is_err(),
                            "Xray must drop TCP header absent in first fragment: opts={option_length}, chained={chained}"
                        );
                        // Same tuple and fragment ID recover when fragment zero
                        // contains the first eight bytes of the TCP header.
                        let recovered_split = extension_length + 8;
                        let good_first =
                            packet(&fragmentable[..recovered_split], 0, true);
                        let good_second = packet(
                            &fragmentable[recovered_split..],
                            recovered_split,
                            false,
                        );
                        sink.send(Packet::new(good_second)).await.unwrap();
                        sink.send(Packet::new(good_first)).await.unwrap();
                    }
                    let reply = tokio::time::timeout(
                        std::time::Duration::from_millis(300),
                        output.next(),
                    )
                    .await
                    .expect("fragmented TCP SYN-ACK timeout")
                    .expect("TCP output channel closed")
                    .expect("TCP output error");
                    assert!(
                        is_any_ip_syn_ack(reply.data()),
                        "valid SYN-ACK opts={option_length} chained={chained} tcp-first={first_tcp_bytes} xray={xray_mode}"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn fragmented_ipv6_tcp_after_destination_options_reassembles() {
    let src = [0x20; 16];
    let dst = [0x21; 16];
    let mut full = Vec::new();
    etherparse::PacketBuilder::ipv6(src, dst, 64)
        .tcp(1234, 80, 0, 65535)
        .syn()
        .write(&mut full, &[])
        .unwrap();
    let mut data = vec![etherparse::ip_number::TCP.0, 0, 0, 0, 0, 0, 0, 0];
    data.extend_from_slice(&full[40..]);
    let build = |part: &[u8], offset: usize, more: bool| {
        let ip = etherparse::Ipv6Header {
            payload_length: (8 + part.len()) as u16,
            next_header: etherparse::ip_number::IPV6_FRAG,
            hop_limit: 64,
            source: src,
            destination: dst,
            ..Default::default()
        };
        let frag = etherparse::Ipv6FragmentHeader::new(
            etherparse::ip_number::IPV6_DEST_OPTIONS,
            etherparse::IpFragOffset::try_new((offset / 8) as u16).unwrap(),
            more,
            0x7788_99aa,
        );
        [ip.to_bytes().as_slice(), frag.to_bytes().as_slice(), part].concat()
    };
    let (stack, mut listener, _udp) = NetStack::new();
    let (mut sink, mut output) = stack.split();
    for packet in [build(&data[16..], 16, false), build(&data[..16], 0, true)] {
        sink.send(Packet::new(packet)).await.unwrap();
    }
    let stream =
        tokio::time::timeout(std::time::Duration::from_millis(300), listener.next())
            .await
            .expect("TCP reassembly timed out")
            .expect("TCP listener closed");
    assert_eq!(stream.local_addr().port(), 1234);
    let reply =
        tokio::time::timeout(std::time::Duration::from_millis(300), output.next())
            .await
            .expect("SYN-ACK timed out")
            .expect("stack closed")
            .expect("stack error");
    assert!(is_any_ip_syn_ack(reply.data()));
}

#[tokio::test]
async fn fragmented_ipv4_tcp_syn_reassembles_out_of_order() {
    let [first, second] = build_ipv4_tcp_syn_fragments();
    let (stack, mut tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    stack_sink.send(Packet::new(second)).await.unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            stack_stream.next(),
        )
        .await
        .is_err(),
        "incomplete IPv4 TCP fragments produced stack output"
    );

    stack_sink.send(Packet::new(first)).await.unwrap();
    let stream = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tcp_listener.next(),
    )
    .await
    .expect("reassembled IPv4 TCP SYN did not create a stream")
    .expect("TCP listener ended unexpectedly");
    assert_eq!(stream.local_addr(), "1.1.1.1:1024".parse().unwrap());
    assert_eq!(stream.remote_addr(), "2.2.2.2:80".parse().unwrap());

    let reply = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_stream.next(),
    )
    .await
    .expect("reassembled IPv4 TCP SYN did not reach smoltcp")
    .expect("stack output ended unexpectedly")
    .expect("stack returned an error");
    assert!(is_any_ip_syn_ack(reply.data()));
}

#[tokio::test]
async fn fragmented_ipv6_tcp_syn_reassembles_out_of_order() {
    let [first, second] = build_ipv6_tcp_syn_fragments();
    let (stack, mut tcp_listener, _udp_socket) = NetStack::new();
    let (mut stack_sink, mut stack_stream) = stack.split();

    stack_sink.send(Packet::new(second)).await.unwrap();
    stack_sink.send(Packet::new(first)).await.unwrap();

    let stream = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        tcp_listener.next(),
    )
    .await
    .expect("reassembled IPv6 TCP SYN did not create a stream")
    .expect("TCP listener ended unexpectedly");
    assert_eq!(stream.local_addr().port(), 1234);
    assert_eq!(stream.remote_addr().port(), 80);
    assert_eq!(
        stream.local_addr().ip(),
        std::net::IpAddr::V6(std::net::Ipv6Addr::from([0x20; 16]))
    );
    assert_eq!(
        stream.remote_addr().ip(),
        std::net::IpAddr::V6(std::net::Ipv6Addr::from([0x21; 16]))
    );

    let reply = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        stack_stream.next(),
    )
    .await
    .expect("reassembled IPv6 TCP SYN did not reach smoltcp")
    .expect("stack output ended unexpectedly")
    .expect("stack returned an error");
    assert!(is_any_ip_syn_ack(reply.data()));
}

#[tokio::test]
async fn invalid_udp_checksum_is_dropped_without_ending_stream() {
    let (stack, _tcp_listener, udp_socket) = NetStack::new();
    let (mut stack_sink, _stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();
    let mut invalid = build_udp_packet().to_vec();
    invalid[26] ^= 0xff;
    stack_sink.send(Packet::new(invalid)).await.unwrap();
    stack_sink
        .send(Packet::new(build_udp_packet()))
        .await
        .unwrap();

    let packet =
        tokio::time::timeout(std::time::Duration::from_millis(300), udp_read.recv())
            .await
            .expect("valid UDP packet was not delivered after bad checksum")
            .expect("UDP receive stream ended unexpectedly");
    assert_eq!(packet.local_addr, "1.1.1.1:5000".parse().unwrap());
}
