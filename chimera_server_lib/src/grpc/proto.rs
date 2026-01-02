pub mod xray {
    pub mod app {
        pub mod stats {
            pub mod command {
                tonic::include_proto!("xray.app.stats.command");
            }
        }
        pub mod log {
            pub mod command {
                tonic::include_proto!("xray.app.log.command");
            }
        }
        pub mod proxyman {
            pub mod command {
                tonic::include_proto!("xray.app.proxyman.command");
            }
        }
        pub mod router {
            pub mod command {
                tonic::include_proto!("xray.app.router.command");
            }
        }
    }
    pub mod core {
        tonic::include_proto!("xray.core");
        pub mod app {
            pub mod observatory {
                tonic::include_proto!("xray.core.app.observatory");
                pub mod command {
                    tonic::include_proto!("xray.core.app.observatory.command");
                }
            }
        }
    }
    pub mod common {
        pub mod serial {
            tonic::include_proto!("xray.common.serial");
        }
        pub mod protocol {
            tonic::include_proto!("xray.common.protocol");
        }
        pub mod net {
            tonic::include_proto!("xray.common.net");
        }
    }
}
