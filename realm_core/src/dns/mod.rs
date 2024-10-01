//! Global dns resolver.

use std::io::{Result, Error, ErrorKind};
use std::net::SocketAddr;
use hickory_resolver as resolver;
use resolver::TokioAsyncResolver;
use resolver::system_conf::read_system_conf;
use resolver::lookup_ip::{LookupIp, LookupIpIter};
pub use resolver::config;
use config::{ResolverOpts, ResolverConfig};

#[cfg(not(feature = "multi-thread"))]
use once_cell::unsync::{OnceCell, Lazy};

#[cfg(feature = "multi-thread")]
use once_cell::{unsync::OnceCell, sync::Lazy};

use crate::endpoint::RemoteAddr;

/// Dns config.
#[derive(Debug, Clone)]
pub struct DnsConf {
    pub conf: ResolverConfig,
    pub opts: ResolverOpts,
}

/// Use system config on unix(except android) or windows,
/// otherwise use google's public dns servers.
impl Default for DnsConf {
    fn default() -> Self {
        #[cfg(any(all(unix, not(target_os = "android")), windows))]
        let (conf, opts) = read_system_conf().unwrap();

        #[cfg(not(any(all(unix, not(target_os = "android")), windows)))]
        let (conf, opts) = Default::default();

        Self { conf, opts }
    }
}

static mut DNS_CONF: OnceCell<DnsConf> = OnceCell::new();

static mut DNS: Lazy<TokioAsyncResolver> = Lazy::new(|| {
    let DnsConf { conf, opts } = unsafe { DNS_CONF.take().unwrap() };
    TokioAsyncResolver::tokio(conf, opts)
});

/// Force initialization.
pub fn force_init() {
    use std::ptr;
    unsafe {
        Lazy::force(&*ptr::addr_of!(DNS));
    }
}

/// Setup global dns resolver. This is not thread-safe!
pub fn build(conf: Option<ResolverConfig>, opts: Option<ResolverOpts>) {
    build_lazy(conf, opts);
    force_init();
}

/// Setup config of global dns resolver, without initialization.
/// This is not thread-safe!
pub fn build_lazy(conf: Option<ResolverConfig>, opts: Option<ResolverOpts>) {
    let mut dns_conf = DnsConf::default();

    if let Some(conf) = conf {
        dns_conf.conf = conf;
    }

    if let Some(opts) = opts {
        dns_conf.opts = opts;
    }

    unsafe {
        DNS_CONF.set(dns_conf).unwrap();
    }
}


/// Lookup ip with global dns resolver.
pub async fn resolve_ip(ip: &str) -> Result<LookupIp> {
    unsafe {
        DNS.lookup_ip(ip)
            .await
            .map_or_else(|e| Err(Error::new(ErrorKind::Other, e)), Ok)
    }
}

/// Lookup socketaddr with global dns resolver.
pub async fn resolve_addr(addr: &RemoteAddr) -> Result<LookupRemoteAddr<'_>> {
    use RemoteAddr::*;
    use LookupRemoteAddr::*;
    match addr {
        SocketAddr(addr) => Ok(NoLookup(addr)),
        DomainName(ip, port) => resolve_ip(ip).await.map(|ip| Dolookup(ip, *port)),
    }
}

/// Lookup socketaddr with global dns resolver.
pub async fn resolve_addr_srv(addr: &RemoteAddr) -> Result<LookupRemoteAddr<'_>> {
    use RemoteAddr::*;
    use LookupRemoteAddr::*;
    match addr {
        SocketAddr(socket_addr) => {
            if socket_addr.port() == 0 && (socket_addr.ip().to_string().contains("._tcp.") || socket_addr.ip().to_string().contains("._udp.")) {
                //解析srv
                let (new_domain, new_port) = resolve_srv(socket_addr.ip().to_string()).await;
                resolve_ip(&new_domain).await.map(|ip| Dolookup(ip, new_port))
            } else {
                Ok(NoLookup(socket_addr))
            }
        },
        DomainName(domain, port) => {
            if *port == 0 && (domain.contains("._tcp.") || domain.contains("._udp.")) {
                //解析srv
                let (new_domain, new_port) = resolve_srv(domain.to_string()).await;
                resolve_ip(&new_domain).await.map(|ip| Dolookup(ip, new_port))
            } else {
                resolve_ip(domain).await.map(|ip| Dolookup(ip, *port))
            }
        },
    }
}

pub async fn resolve_srv(srv_host: String) -> (String, u16) {
    unsafe {
        log::info!("resolve_srv===={}",srv_host);
        DNS.clear_cache();
        let result = DNS.srv_lookup(srv_host).await;
        let srv_records = result.unwrap();
        for record in srv_records {
            let target = record.target().to_string();
            let port = record.port();
            log::info!("resolve_srv result====target:{} port:{}", target, port);
            return (target, port);
        }
        log::info!("resolve_srv error");
        (String::from("0.0.0.0"), 0)
    }
}

/// Resolved result.
pub enum LookupRemoteAddr<'a> {
    NoLookup(&'a SocketAddr),
    Dolookup(LookupIp, u16),
}

impl LookupRemoteAddr<'_> {
    /// Get view of resolved result.
    pub fn iter(&self) -> LookupRemoteAddrIter {
        use LookupRemoteAddr::*;
        match self {
            NoLookup(addr) => LookupRemoteAddrIter::NoLookup(std::iter::once(addr)),
            Dolookup(ip, port) => LookupRemoteAddrIter::DoLookup(ip.iter(), *port),
        }
    }
}

/// View of resolved result.
pub enum LookupRemoteAddrIter<'a> {
    NoLookup(std::iter::Once<&'a SocketAddr>),
    DoLookup(LookupIpIter<'a>, u16),
}

impl Iterator for LookupRemoteAddrIter<'_> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        use LookupRemoteAddrIter::*;
        match self {
            NoLookup(addr) => addr.next().copied(),
            DoLookup(ip, port) => ip.next().map(|ip| SocketAddr::new(ip, *port)),
        }
    }
}
