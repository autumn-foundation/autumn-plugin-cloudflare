//! Cloudflare IP ranges.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::core::{prefix_match_v4, prefix_match_v6, range_is_safe};

/// The published list on 2026-10-11 (`GET /client/v4/ips`).
const BUILTIN: [&str; 22] = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// An error in an IP range or a range list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    /// The text is not a valid range.
    #[error("invalid IP range `{0}`")]
    Invalid(String),
    /// The range is too broad for a Cloudflare list.
    #[error("IP range `{0}` is too broad")]
    TooBroad(String),
    /// The list has no ranges.
    #[error("the range list is empty")]
    Empty,
    /// The API response is not valid, or the request failed.
    #[error("invalid range list from the Cloudflare API: {0}")]
    Api(String),
}

/// An IP range in CIDR notation, for example `104.16.0.0/13`. An address
/// with no prefix is a range of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    network: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// The network address.
    #[must_use]
    pub const fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// True when `ip` is in this range. An IPv4 range does not match an
    /// IPv6 address. Use [`CloudflareRanges::contains`] for IPv4-mapped
    /// IPv6 addresses.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => prefix_match_v4(n.into(), self.prefix, a.into()),
            (IpAddr::V6(n), IpAddr::V6(a)) => prefix_match_v6(n.into(), self.prefix, a.into()),
            _ => false,
        }
    }

    const fn is_safe(&self) -> bool {
        range_is_safe(self.network.is_ipv4(), self.prefix)
    }
}

impl FromStr for IpRange {
    type Err = RangeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || RangeError::Invalid(s.to_owned());
        let text = s.trim();
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = addr.parse().map_err(|_| invalid())?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().map_err(|_| invalid())?,
            None => max,
        };
        if prefix > max {
            return Err(invalid());
        }
        Ok(Self { network, prefix })
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// A list of Cloudflare edge ranges. The list is never empty. No range is
/// broader than `/8` (IPv4) or `/16` (IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRanges {
    ranges: Vec<IpRange>,
}

impl CloudflareRanges {
    /// The built-in snapshot of the published list.
    #[must_use]
    pub fn builtin() -> Self {
        let ranges = BUILTIN.iter().filter_map(|r| r.parse().ok()).collect();
        Self { ranges }
    }

    /// A list from range strings.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty list, a bad range, or a range that is
    /// too broad.
    pub fn parse<I, S>(ranges: I) -> Result<Self, RangeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Vec::new();
        for text in ranges {
            let range: IpRange = text.as_ref().parse()?;
            if !range.is_safe() {
                return Err(RangeError::TooBroad(range.to_string()));
            }
            list.push(range);
        }
        if list.is_empty() {
            return Err(RangeError::Empty);
        }
        Ok(Self { ranges: list })
    }

    /// A list from the body of `GET /client/v4/ips`.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is not a successful API response or
    /// when the list is not safe.
    pub fn from_api_json(body: &[u8]) -> Result<Self, RangeError> {
        #[derive(serde::Deserialize)]
        struct Response {
            success: bool,
            result: Option<Lists>,
        }
        #[derive(serde::Deserialize)]
        struct Lists {
            #[serde(default)]
            ipv4_cidrs: Vec<String>,
            #[serde(default)]
            ipv6_cidrs: Vec<String>,
        }
        let response: Response =
            serde_json::from_slice(body).map_err(|e| RangeError::Api(e.to_string()))?;
        let Response {
            success: true,
            result: Some(lists),
        } = response
        else {
            return Err(RangeError::Api("the API did not return success".to_owned()));
        };
        Self::parse(lists.ipv4_cidrs.iter().chain(&lists.ipv6_cidrs))
    }

    /// The ranges.
    #[must_use]
    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }

    /// True when `ip` is in a range. An IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`) is checked as IPv4.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.ranges.iter().any(|r| r.contains(ip))
    }
}

/// True when `ip` is in one of `ranges`. Checks IPv4-mapped addresses as
/// IPv4.
pub(crate) fn any_contains(ranges: &[IpRange], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ranges.iter().any(|r| r.contains(ip))
}
