use std::{env, error::Error, net::SocketAddr, time::Duration};

use prost::Message;
use tonic::{
    Request,
    codegen::http::uri::PathAndQuery,
    transport::{Channel, Endpoint},
};

const ADD_RULE_PATH: &str = "/xray.app.router.command.RoutingService/AddRule";

#[derive(Clone, PartialEq, Message)]
struct RouterConfig {
    #[prost(int32, tag = "1")]
    domain_strategy: i32,
    #[prost(message, repeated, tag = "2")]
    rule: Vec<RoutingRule>,
}

#[derive(Clone, PartialEq, Message)]
struct RoutingRule {
    #[prost(oneof = "routing_rule::TargetTag", tags = "1, 12")]
    target_tag: Option<routing_rule::TargetTag>,
    #[prost(string, tag = "19")]
    rule_tag: String,
    #[prost(message, repeated, tag = "10")]
    ip: Vec<IpRule>,
    #[prost(int32, repeated, tag = "13")]
    networks: Vec<i32>,
    #[prost(string, repeated, tag = "7")]
    user_email: Vec<String>,
    #[prost(string, repeated, tag = "8")]
    inbound_tag: Vec<String>,
}

mod routing_rule {
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum TargetTag {
        #[prost(string, tag = "1")]
        Tag(String),
        #[prost(string, tag = "12")]
        BalancingTag(String),
    }
}

#[derive(Clone, PartialEq, Message)]
struct IpRule {
    #[prost(message, optional, tag = "2")]
    custom: Option<CidrRule>,
}

#[derive(Clone, PartialEq, Message)]
struct CidrRule {
    #[prost(message, optional, tag = "1")]
    cidr: Option<Cidr>,
    #[prost(bool, tag = "2")]
    reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
struct TypedMessage {
    #[prost(string, tag = "1")]
    r#type: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct AddRuleRequest {
    #[prost(message, optional, tag = "1")]
    config: Option<TypedMessage>,
    #[prost(bool, tag = "2")]
    should_append: bool,
}

#[derive(Clone, PartialEq, Message)]
struct AddRuleResponse {}

fn protected_overlay_tcp_udp_rule() -> RoutingRule {
    RoutingRule {
        target_tag: Some(routing_rule::TargetTag::Tag(
            "overlay-default-deny".into(),
        )),
        rule_tag: "tun-live-update-tcp-udp-deny".into(),
        ip: vec![IpRule {
            custom: Some(CidrRule {
                cidr: Some(Cidr {
                    ip: [10, 44, 0, 0].into(),
                    prefix: 24,
                }),
                reverse_match: false,
            }),
        }],
        // Pinned Xray common.net.Network enum values: TCP=2, UDP=3.
        networks: vec![2, 3],
        user_email: vec!["office-gateway@example.test".into()],
        inbound_tag: vec!["hub-vless-in".into()],
    }
}

async fn connect(address: SocketAddr) -> Result<Channel, Box<dyn Error>> {
    Ok(Endpoint::from_shared(format!("http://{address}"))?
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(2))
        .connect()
        .await?)
}

async fn grpc_unary<RequestMessage, ResponseMessage>(
    channel: Channel,
    path: &'static str,
    request: RequestMessage,
) -> Result<ResponseMessage, tonic::Status>
where
    RequestMessage: Message + Default + Send + Sync + 'static,
    ResponseMessage: Message + Default + Send + Sync + 'static,
{
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.map_err(|error| {
        tonic::Status::unknown(format!("RoutingService is not ready: {error}"))
    })?;
    grpc.unary(
        Request::new(request),
        PathAndQuery::from_static(path),
        tonic_prost::ProstCodec::default(),
    )
    .await
    .map(|response| response.into_inner())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let address = env::args()
        .nth(1)
        .ok_or("usage: tun_policy_update <api-socket-addr>")?
        .parse::<SocketAddr>()?;
    let typed_config = TypedMessage {
        r#type: "xray.app.router.Config".into(),
        value: RouterConfig {
            domain_strategy: 0,
            rule: vec![protected_overlay_tcp_udp_rule()],
        }
        .encode_to_vec(),
    };
    grpc_unary::<AddRuleRequest, AddRuleResponse>(
        connect(address).await?,
        ADD_RULE_PATH,
        AddRuleRequest {
            config: Some(typed_config),
            should_append: false,
        },
    )
    .await?;
    println!("installed live TCP/UDP deny rule for 10.44.0.0/24");
    Ok(())
}
