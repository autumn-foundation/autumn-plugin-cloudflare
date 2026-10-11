//! Cloudflare IP ranges.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

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
    /// The API response is not valid.
    #[error("invalid range list from the Cloudflare API: {0}")]
    Api(String),
}

/// An IP range in CIDR notation, for example `104.16.0.0/13`.
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

    /// True when `ip` is in this range.
    #[must_use]
    pub fn contains(&self, _ip: IpAddr) -> bool {
        todo!()
    }
}

impl FromStr for IpRange {
    type Err = RangeError;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// The Cloudflare edge ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRanges {
    ranges: Vec<IpRange>,
}

impl CloudflareRanges {
    /// The built-in snapshot of the published list.
    #[must_use]
    pub fn builtin() -> Self {
        todo!()
    }

    /// A list from range strings.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty list, a bad range, or a range that is
    /// too broad.
    pub fn parse<I, S>(_ranges: I) -> Result<Self, RangeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        todo!()
    }

    /// A list from the body of `GET /client/v4/ips`.
    ///
    /// # Errors
    ///
    /// Returns an error when the body is not a successful API response or
    /// when the list is not safe.
    pub fn from_api_json(_body: &[u8]) -> Result<Self, RangeError> {
        todo!()
    }

    /// The ranges.
    #[must_use]
    pub fn ranges(&self) -> &[IpRange] {
        &self.ranges
    }

    /// True when `ip` is in a range.
    #[must_use]
    pub fn contains(&self, _ip: IpAddr) -> bool {
        todo!()
    }
}
