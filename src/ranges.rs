//! Cloudflare IP ranges.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::core::{
    MAX_RANGES, MAX_V4_COVERAGE, MAX_V6_COVERAGE, prefix_match_v4, prefix_match_v6, range_is_safe,
};

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

/// Ranges that a Cloudflare list from the API must not touch: private,
/// loopback, link-local, shared (CGNAT), and unspecified addresses.
const NOT_PUBLIC: [&str; 12] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
];

/// An error in an IP range or a range list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
    /// The list has too many ranges, or it covers too many addresses.
    #[error("the range list is too large")]
    TooLarge,
    /// A range from the API touches private, loopback, or link-local
    /// addresses.
    #[error("IP range `{0}` is not public")]
    NotPublic(String),
    /// The API response is not valid, or the request failed.
    #[error("invalid range list from the Cloudflare API: {0}")]
    Api(String),
}

/// An IP range in CIDR notation, for example `104.16.0.0/13`. An address
/// with no prefix is a range of one address. The range clears the host
/// bits, so `10.1.2.3/8` and `10.0.0.0/8` are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpRange {
    network: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// Makes a range.
    ///
    /// # Errors
    ///
    /// Returns an error when `prefix` is more than 32 (IPv4) or 128 (IPv6).
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, RangeError> {
        let network = match addr {
            IpAddr::V4(a) if prefix <= 32 => {
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V4((u32::from(a) & mask).into())
            }
            IpAddr::V6(a) if prefix <= 128 => {
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V6((u128::from(a) & mask).into())
            }
            _ => return Err(RangeError::Invalid(format!("{addr}/{prefix}"))),
        };
        Ok(Self { network, prefix })
    }

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

    /// Returns true when `ip` is in this range. An IPv4 range does not match an
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

    /// The number of addresses in the range.
    fn size(&self) -> u128 {
        let bits = if self.network.is_ipv4() { 32 } else { 128 };
        1u128
            .checked_shl(bits - u32::from(self.prefix))
            .unwrap_or(u128::MAX)
    }

    /// Returns true when the two ranges share an address.
    fn overlaps(&self, other: &Self) -> bool {
        self.contains(other.network) || other.contains(self.network)
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
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().map_err(|_| invalid())?,
            None if network.is_ipv4() => 32,
            None => 128,
        };
        Self::new(network, prefix).map_err(|_| invalid())
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// A list of Cloudflare edge ranges.
///
/// The list is never empty. It has 1,024 ranges or fewer. No range is
/// broader than `/8` (IPv4) or `/16` (IPv6). All IPv4 ranges together
/// cover one `/8` or less. All IPv6 ranges together cover one `/16` or
/// less.
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

    /// Makes a list from range strings.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty list, a bad range, a range that is
    /// too broad, or a list that is too large.
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
            if list.len() == MAX_RANGES {
                return Err(RangeError::TooLarge);
            }
            list.push(range);
        }
        if list.is_empty() {
            return Err(RangeError::Empty);
        }
        let (mut v4, mut v6) = (0u128, 0u128);
        for range in &list {
            let total = if range.network.is_ipv4() {
                &mut v4
            } else {
                &mut v6
            };
            *total = total.saturating_add(range.size());
        }
        if v4 > MAX_V4_COVERAGE || v6 > MAX_V6_COVERAGE {
            return Err(RangeError::TooLarge);
        }
        Ok(Self { ranges: list })
    }

    /// Makes a list from the body of `GET /client/v4/ips`.
    ///
    /// The function also rejects ranges that touch private, loopback,
    /// link-local, or shared (CGNAT) addresses.
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
        let ranges = Self::parse(lists.ipv4_cidrs.iter().chain(&lists.ipv6_cidrs))?;
        let blocked: Vec<IpRange> = NOT_PUBLIC.iter().filter_map(|r| r.parse().ok()).collect();
        if let Some(bad) = ranges
            .ranges
            .iter()
            .find(|r| blocked.iter().any(|b| b.overlaps(r)))
        {
            return Err(RangeError::NotPublic(bad.to_string()));
        }
        Ok(ranges)
    }

    /// The ranges.
    #[must_use]
    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }

    /// Returns true when `ip` is in a range. An IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`) is checked as IPv4.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        any_contains(&self.ranges, ip)
    }
}

/// Returns true when `ip` is in one of `ranges`. Checks IPv4-mapped addresses as
/// IPv4.
pub(crate) fn any_contains(ranges: &[IpRange], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ranges.iter().any(|r| r.contains(ip))
}
