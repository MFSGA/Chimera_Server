use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindLocation {
    Address(NetLocation),
}

impl std::fmt::Display for BindLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindLocation::Address(n) => write!(f, "{}", n),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct NetLocation {
    address: Address,
    port: u16,
}

impl NetLocation {
    pub const UNSPECIFIED: Self = NetLocation::new(Address::UNSPECIFIED, 0);

    pub const fn new(address: Address, port: u16) -> Self {
        Self { address, port }
    }

    pub fn _is_unspecified(&self) -> bool {
        self == &Self::UNSPECIFIED
    }

    pub fn from_str(s: &str, default_port: Option<u16>) -> std::io::Result<Self> {
        let (address_str, port, expect_ipv6) = match s.rfind(':') {
            Some(i) => match s[i + 1..].parse::<u16>() {
                Ok(port) => (&s[0..i], Some(port), false),
                Err(_) => (s, default_port, true),
            },
            None => (s, default_port, false),
        };

        let address = Address::from(address_str)?;
        if expect_ipv6 && !address.is_ipv6() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid location",
            ));
        }

        let port = port.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "No port"))?;

        Ok(Self { address, port })
    }

    pub fn from_ip_addr(ip: IpAddr, port: u16) -> Self {
        let address = match ip {
            IpAddr::V4(addr) => Address::Ipv4(addr),
            IpAddr::V6(addr) => Address::Ipv6(addr),
        };
        Self { address, port }
    }

    pub fn components(&self) -> (&Address, u16) {
        (&self.address, self.port)
    }

    pub fn unwrap_components(self) -> (Address, u16) {
        (self.address, self.port)
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn to_socket_addr(&self) -> std::io::Result<SocketAddr> {
        match self.address {
            Address::Ipv6(ref addr) => Ok(SocketAddr::new(IpAddr::V6(*addr), self.port)),
            Address::Ipv4(ref addr) => Ok(SocketAddr::new(IpAddr::V4(*addr), self.port)),

            Address::Hostname(ref d) => format!("{}:{}", d, self.port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Lookup failed")),
        }
    }

    pub fn to_socket_addr_nonblocking(&self) -> Option<SocketAddr> {
        match self.address {
            Address::Ipv6(ref addr) => Some(SocketAddr::new(IpAddr::V6(*addr), self.port)),
            Address::Ipv4(ref addr) => Some(SocketAddr::new(IpAddr::V4(*addr), self.port)),
            Address::Hostname(ref _d) => None,
        }
    }
}

impl std::fmt::Display for NetLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:{}", self.address, self.port)
    }
}

fn deserialize_net_location<'de, D>(
    deserializer: D,
    default_port: Option<u16>,
) -> Result<NetLocation, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let net_location = NetLocation::from_str(&value, default_port).map_err(|_| {
        serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("invalid net location"),
            &"invalid net location",
        )
    })?;

    Ok(net_location)
}

impl<'de> serde::de::Deserialize<'de> for NetLocation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserialize_net_location(deserializer, None)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Address {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Hostname(String),
}

impl Address {
    pub const UNSPECIFIED: Self = Address::Ipv4(Ipv4Addr::UNSPECIFIED);

    pub fn from(s: &str) -> std::io::Result<Self> {
        let mut dots = 0;
        let mut possible_ipv4 = true;
        let mut possible_ipv6 = true;
        let mut possible_hostname = true;
        for b in s.as_bytes().iter() {
            let c = *b;
            if c == b':' {
                possible_ipv4 = false;
                possible_hostname = false;
                break;
            } else if c == b'.' {
                possible_ipv6 = false;
                dots += 1;
                if dots > 3 {
                    break;
                }
            } else if (b'A'..=b'F').contains(&c) || (b'a'..=b'f').contains(&c) {
                possible_ipv4 = false;
            } else if !c.is_ascii_digit() {
                possible_ipv4 = false;
                possible_ipv6 = false;
                break;
            }
        }

        if possible_ipv4 && dots == 3 {
            if let Ok(addr) = s.parse::<Ipv4Addr>() {
                return Ok(Address::Ipv4(addr));
            }
        }

        if possible_ipv6 {
            if let Ok(addr) = s.parse::<Ipv6Addr>() {
                return Ok(Address::Ipv6(addr));
            }
        }

        if possible_hostname {
            return Ok(Address::Hostname(s.to_string()));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse address: {}", s),
        ))
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Address::Ipv6(_))
    }

    pub fn is_hostname(&self) -> bool {
        matches!(self, Address::Hostname(_))
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            Address::Hostname(ref hostname) => Some(hostname),
            _ => None,
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Address::Ipv4(i) => write!(f, "{}", i),
            Address::Ipv6(i) => write!(f, "{}", i),
            Address::Hostname(h) => write!(f, "{}", h),
        }
    }
}
