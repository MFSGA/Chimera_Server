mod xhttp_support;

use std::net::{Ipv4Addr, SocketAddr};

use serde_json::json;
use xhttp_support::{
    TEST_UUID, assert_socks5_echo, create_test_dir, deterministic_payload,
    free_localhost_port, serial_xray_guard, start_chimera, start_tcp_echo_server,
    start_xray, wait_for_tcp, workspace_root, write_json,
};

#[derive(Clone, Copy)]
struct XhttpCase {
    name: &'static str,
    mode: &'static str,
    uplink_method: &'static str,
    session_placement: &'static str,
    seq_placement: &'static str,
    data_placement: &'static str,
    server_max_header_bytes: i32,
    padding_obfs: bool,
    padding_placement: &'static str,
    padding_method: &'static str,
    no_grpc_header: bool,
    no_sse_header: bool,
}

fn run_xhttp_case(case: XhttpCase) {
    let _serial = serial_xray_guard();
    let workspace = workspace_root();
    let work_dir = create_test_dir(case.name);
    let echo_addr = start_tcp_echo_server();
    let chimera_port = free_localhost_port();
    let xray_socks_port = free_localhost_port();
    let chimera_config_path = work_dir.join("chimera.json");
    let xray_config_path = work_dir.join("xray.json");

    write_json(
        &chimera_config_path,
        json!({
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": chimera_port,
                "protocol": "vless",
                "tag": format!("chimera-xhttp-{}", case.name),
                "settings": {
                    "clients": [{
                        "id": TEST_UUID,
                        "email": format!("{}@xhttp.matrix", case.name)
                    }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "path": "/xhttp?matrix=1",
                        "mode": case.mode,
                        "uplinkHTTPMethod": "POST",
                        "headers": {"X-Matrix-Server": case.name},
                        "noGRPCHeader": case.no_grpc_header,
                        "noSSEHeader": case.no_sse_header,
                        "serverMaxHeaderBytes": case.server_max_header_bytes,
                        "xPaddingBytes": {"from": 100, "to": 256},
                        "xPaddingObfsMode": case.padding_obfs,
                        "xPaddingKey": "x_matrix_padding",
                        "xPaddingHeader": "X-Matrix-Padding",
                        "xPaddingPlacement": case.padding_placement,
                        "xPaddingMethod": case.padding_method,
                        "scMaxEachPostBytes": {"from": 128 * 1024, "to": 128 * 1024},
                        "scMaxBufferedPosts": 32,
                        "scMinPostsIntervalMs": {"from": 1, "to": 1},
                        "scStreamUpServerSecs": {"from": 1, "to": 1},
                        "sessionIDPlacement": case.session_placement,
                        "sessionIDKey": "x_matrix_session",
                        "sessionIDTable": "Base62",
                        "sessionIDLength": {"from": 16, "to": 16},
                        "seqPlacement": case.seq_placement,
                        "seqKey": "x_matrix_seq",
                        "uplinkDataPlacement": case.data_placement,
                        "uplinkDataKey": "x_matrix_data",
                        "uplinkChunkSize": {"from": 2048, "to": 3072}
                    }
                }
            }],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}]
        }),
    );
    write_json(
        &xray_config_path,
        json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": xray_socks_port,
                "protocol": "socks",
                "tag": "socks-in",
                "settings": {"auth": "noauth"}
            }],
            "outbounds": [{
                "tag": "to-chimera",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": chimera_port,
                        "users": [{"id": TEST_UUID, "encryption": "none"}]
                    }]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "security": "none",
                    "xhttpSettings": {
                        "path": "/xhttp?matrix=1",
                        "mode": case.mode,
                        "uplinkHTTPMethod": case.uplink_method,
                        "noGRPCHeader": case.no_grpc_header,
                        "noSSEHeader": case.no_sse_header,
                        "xPaddingBytes": "100-256",
                        "xPaddingObfsMode": case.padding_obfs,
                        "xPaddingKey": "x_matrix_padding",
                        "xPaddingHeader": "X-Matrix-Padding",
                        "xPaddingPlacement": case.padding_placement,
                        "xPaddingMethod": case.padding_method,
                        "scMinPostsIntervalMs": 1,
                        "sessionPlacement": if case.session_placement == "path" { "" } else { case.session_placement },
                        "sessionKey": "x_matrix_session",
                        "sessionIDPlacement": if case.session_placement == "path" { "" } else { case.session_placement },
                        "sessionIDKey": "x_matrix_session",
                        "sessionIDTable": "Base62",
                        "sessionIDLength": 16,
                        "seqPlacement": if case.seq_placement == "path" { "" } else { case.seq_placement },
                        "seqKey": "x_matrix_seq",
                        "uplinkDataPlacement": if case.data_placement == "auto" { "" } else { case.data_placement },
                        "uplinkDataKey": "x_matrix_data",
                        "uplinkChunkSize": 2048
                    }
                }
            }]
        }),
    );

    let mut chimera = start_chimera(&workspace, &work_dir, &chimera_config_path);
    wait_for_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, chimera_port)));
    chimera.assert_running();
    let mut xray = start_xray(&workspace, &work_dir, &xray_config_path);
    let socks_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, xray_socks_port));
    wait_for_tcp(socks_addr);
    xray.assert_running();

    assert_socks5_echo(
        socks_addr,
        echo_addr,
        format!("XHTTP matrix {}", case.name).as_bytes(),
    );
    assert_socks5_echo(socks_addr, echo_addr, &deterministic_payload(64 * 1024));
}

macro_rules! xhttp_case {
    ($test:ident, $mode:literal, $method:literal, $session:literal, $seq:literal,
     $data:literal, $header_limit:expr, $obfs:expr, $padding_place:literal,
     $padding_method:literal, $no_grpc:expr, $no_sse:expr) => {
        #[test]
        #[ignore = "starts Chimera and Xray for one XHTTP interoperability matrix case"]
        fn $test() {
            run_xhttp_case(XhttpCase {
                name: stringify!($test),
                mode: $mode,
                uplink_method: $method,
                session_placement: $session,
                seq_placement: $seq,
                data_placement: $data,
                server_max_header_bytes: $header_limit,
                padding_obfs: $obfs,
                padding_placement: $padding_place,
                padding_method: $padding_method,
                no_grpc_header: $no_grpc,
                no_sse_header: $no_sse,
            });
        }
    };
}

#[rustfmt::skip]
xhttp_case!(stream_one_patch_body, "stream-one", "PATCH", "header", "header", "body", 8192, false, "queryInHeader", "repeat-x", true, true);
#[rustfmt::skip]
xhttp_case!(stream_one_post_auto, "stream-one", "POST", "path", "path", "auto", 0, false, "queryInHeader", "repeat-x", false, false);
#[rustfmt::skip]
xhttp_case!(packet_post_body_path, "packet-up", "POST", "path", "path", "body", 8192, false, "queryInHeader", "repeat-x", true, false);
#[rustfmt::skip]
xhttp_case!(packet_post_header_query, "packet-up", "POST", "header", "query", "header", 131072, false, "queryInHeader", "repeat-x", true, false);
#[rustfmt::skip]
xhttp_case!(packet_post_cookie_header, "packet-up", "POST", "cookie", "header", "cookie", 131072, false, "queryInHeader", "repeat-x", true, false);
#[rustfmt::skip]
xhttp_case!(packet_get_body_query_cookie, "packet-up", "GET", "query", "cookie", "body", 8192, false, "queryInHeader", "repeat-x", true, false);
#[rustfmt::skip]
xhttp_case!(packet_patch_auto_header_cookie, "packet-up", "PATCH", "header", "cookie", "auto", 8192, false, "queryInHeader", "repeat-x", false, false);
#[rustfmt::skip]
xhttp_case!(stream_up_put_cookie, "stream-up", "PUT", "cookie", "header", "body", 8192, false, "queryInHeader", "repeat-x", true, false);
#[rustfmt::skip]
xhttp_case!(stream_up_patch_path_pair, "stream-up", "PATCH", "path", "path", "body", 8192, false, "queryInHeader", "repeat-x", false, false);
#[rustfmt::skip]
xhttp_case!(auto_post_path_pair, "auto", "POST", "path", "path", "body", 8192, false, "queryInHeader", "repeat-x", true, false);
#[rustfmt::skip]
xhttp_case!(stream_one_obfs_header, "stream-one", "PATCH", "header", "header", "body", 8192, true, "header", "repeat-x", true, true);
#[rustfmt::skip]
xhttp_case!(packet_cookie_obfs_tokenish, "packet-up", "POST", "cookie", "header", "cookie", 131072, true, "cookie", "tokenish", true, false);
#[rustfmt::skip]
xhttp_case!(packet_body_obfs_query, "packet-up", "POST", "query", "cookie", "body", 8192, true, "query", "tokenish", true, false);
#[rustfmt::skip]
xhttp_case!(stream_up_obfs_referer, "stream-up", "PUT", "header", "query", "body", 8192, true, "queryInHeader", "repeat-x", false, false);
