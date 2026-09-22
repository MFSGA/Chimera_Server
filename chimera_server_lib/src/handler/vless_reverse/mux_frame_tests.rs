use super::*;

fn destination(network: TargetNetwork, address: Address, port: u16) -> Destination {
    Destination {
        network,
        location: NetLocation::new(address, port),
    }
}

#[test]
fn new_tcp_frame_matches_xray_wire_vector() {
    let metadata = FrameMetadata {
        session_id: 1,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(destination(
            TargetNetwork::Tcp,
            Address::Hostname("example.com".into()),
            80,
        )),
        source: None,
        local: None,
        global_id: None,
    };
    let mut encoded = BytesMut::new();
    metadata.encode(&mut encoded).expect("encode TCP metadata");

    let expected = [
        0x00, 0x14, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x50, 0x02, 0x0b, b'e',
        b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
    ];
    assert_eq!(encoded.as_ref(), expected);

    let decoded = FrameMetadata::decode(&mut encoded, false)
        .expect("decode TCP metadata")
        .expect("complete TCP metadata");
    assert_eq!(decoded, metadata);
    assert_eq!(decoded.transfer_type(), Some(TransferType::Stream));
    assert!(encoded.is_empty());
}

#[test]
fn reverse_new_frame_round_trips_source_and_local_metadata() {
    let metadata = FrameMetadata {
        session_id: 9,
        status: SessionStatus::New,
        option: FrameOption::default(),
        target: Some(destination(
            TargetNetwork::Tcp,
            Address::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
            443,
        )),
        source: Some(destination(
            TargetNetwork::Tcp,
            Address::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            50_000,
        )),
        local: Some(destination(
            TargetNetwork::Tcp,
            Address::Ipv4(Ipv4Addr::new(203, 0, 113, 5)),
            8443,
        )),
        global_id: None,
    };
    let mut encoded = BytesMut::new();
    metadata
        .encode(&mut encoded)
        .expect("encode Reverse metadata");
    assert_eq!(
        encoded.as_ref(),
        [
            0x00, 0x1c, 0x00, 0x09, 0x01, 0x00, 0x01, 0x01, 0xbb, 0x01, 10, 0, 0, 2,
            0x01, 0xc3, 0x50, 0x01, 192, 0, 2, 10, 0x01, 0x20, 0xfb, 0x01, 203, 0,
            113, 5,
        ]
    );

    let decoded = FrameMetadata::decode(&mut encoded, true)
        .expect("decode Reverse metadata")
        .expect("complete Reverse metadata");
    assert_eq!(decoded, metadata);
}

#[test]
fn udp_global_id_and_packet_transfer_type_round_trip() {
    let metadata = FrameMetadata {
        session_id: 12,
        status: SessionStatus::New,
        option: FrameOption::default().with_data(),
        target: Some(destination(
            TargetNetwork::Udp,
            Address::Hostname("dns.example".into()),
            53,
        )),
        source: None,
        local: None,
        global_id: Some([1, 2, 3, 4, 5, 6, 7, 8]),
    };
    let mut encoded = BytesMut::new();
    metadata.encode(&mut encoded).expect("encode UDP metadata");

    let decoded = FrameMetadata::decode(&mut encoded, false)
        .expect("decode UDP metadata")
        .expect("complete UDP metadata");
    assert_eq!(decoded, metadata);
    assert_eq!(decoded.transfer_type(), Some(TransferType::Packet));
}

#[test]
fn malformed_length_status_and_address_fail_closed() {
    let mut oversized = BytesMut::from(&[0x02, 0x01][..]);
    let error = FrameMetadata::decode(&mut oversized, true)
        .expect_err("metadata larger than 512 bytes must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let mut unknown_status =
        BytesMut::from(&[0x00, 0x04, 0x00, 0x01, 0xff, 0x00][..]);
    let error = FrameMetadata::decode(&mut unknown_status, true)
        .expect_err("unknown session status must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    let mut truncated_target = BytesMut::from(
        &[0x00, 0x08, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x50, 0x01][..],
    );
    let error = FrameMetadata::decode(&mut truncated_target, true)
        .expect_err("truncated target address must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn incomplete_frame_waits_without_consuming_input() {
    let raw = [0x00, 0x14, 0x00, 0x01, 0x01];
    let mut input = BytesMut::from(&raw[..]);
    assert!(
        FrameMetadata::decode(&mut input, true)
            .expect("partial metadata should wait")
            .is_none()
    );
    assert_eq!(input.as_ref(), raw);
}

#[test]
fn duplicate_session_id_fails_closed_until_end() {
    let new = FrameMetadata {
        session_id: 42,
        status: SessionStatus::New,
        option: FrameOption::default(),
        target: Some(destination(
            TargetNetwork::Tcp,
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            80,
        )),
        source: None,
        local: None,
        global_id: None,
    };
    let mut tracker = SessionIdTracker::default();
    tracker
        .observe(&new)
        .expect("first session id is available");

    let error = tracker
        .observe(&new)
        .expect_err("duplicate New session id must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

    tracker
        .observe(&FrameMetadata {
            session_id: 42,
            status: SessionStatus::End,
            option: FrameOption::default(),
            target: None,
            source: None,
            local: None,
            global_id: None,
        })
        .expect("end releases the session id");
    tracker
        .observe(&new)
        .expect("session id can be reused after End");
}

#[test]
fn encode_rejects_invalid_reverse_metadata_shapes() {
    let mut encoded = BytesMut::new();
    let error = FrameMetadata {
        session_id: 1,
        status: SessionStatus::New,
        option: FrameOption::default(),
        target: Some(destination(
            TargetNetwork::Tcp,
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            80,
        )),
        source: None,
        local: Some(destination(
            TargetNetwork::Tcp,
            Address::Ipv4(Ipv4Addr::LOCALHOST),
            81,
        )),
        global_id: None,
    }
    .encode(&mut encoded)
    .expect_err("local metadata without source must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(encoded.is_empty());

    let long = "a".repeat(255);
    let error = FrameMetadata {
        session_id: 2,
        status: SessionStatus::New,
        option: FrameOption::default(),
        target: Some(destination(
            TargetNetwork::Tcp,
            Address::Hostname(long.clone()),
            80,
        )),
        source: Some(destination(
            TargetNetwork::Tcp,
            Address::Hostname(long.clone()),
            81,
        )),
        local: Some(destination(TargetNetwork::Tcp, Address::Hostname(long), 82)),
        global_id: None,
    }
    .encode(&mut encoded)
    .expect_err("metadata larger than 512 bytes must fail");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(encoded.is_empty());
}

#[test]
fn frame_options_match_xray_bit_assignments() {
    assert_eq!(FrameOption::default().with_data().raw(), 0x01);
    assert_eq!(FrameOption::default().with_error().raw(), 0x02);
}
