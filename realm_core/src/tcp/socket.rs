use std::io::{Result, Error, ErrorKind};
use std::net::SocketAddr;
use std::time::Duration;
use tokio;
use realm_syscall::new_tcp_socket;
use tokio::net::{TcpSocket, TcpStream, TcpListener};
use crate::dns::{lookup_srv, resolve_addr};
use crate::time::timeoutfut;
use crate::endpoint::{RemoteAddr, BindOpts, ConnectOpts};

pub fn bind(laddr: &SocketAddr, bind_opts: BindOpts) -> Result<TcpListener> {
    let BindOpts { ipv6_only } = bind_opts;
    let socket = new_tcp_socket(laddr)?;

    // ipv6_only
    if let SocketAddr::V6(_) = laddr {
        socket.set_only_v6(ipv6_only)?;
    }

    // ignore error
    let _ = socket.set_reuse_address(true);

    socket.bind(&(*laddr).into())?;
    socket.listen(1024)?;

    TcpListener::from_std(socket.into())
}

//解析srv
pub async fn resolve_srv(raddr: &RemoteAddr) -> RemoteAddr {
    match raddr {
        RemoteAddr::SocketAddr(socket_addr) => {
            let (new_ip, new_port) = lookup_srv(socket_addr.ip().to_string()).await;
            if let Ok(new_socket_addr) = format!("{}:{}", new_ip, new_port).parse::<SocketAddr>() {
                return RemoteAddr::SocketAddr(new_socket_addr)
            }
        }
        RemoteAddr::DomainName(domain, _port) => {
            let (new_ip, new_port) = lookup_srv(domain.to_string()).await;
            return RemoteAddr::DomainName(new_ip, new_port);
        }
    }
    raddr.clone() // 返回对修改后 addr 的引用
}

/**
 * 判断是否是SRV格式
 * */
pub async fn is_srv(raddr: &RemoteAddr) -> bool {
    match raddr {
        RemoteAddr::SocketAddr(addr) => addr.port() == 0 && (addr.ip().to_string().contains("._tcp.") || addr.ip().to_string().contains("._udp.")),
        RemoteAddr::DomainName(domain, port) => *port == 0 && (domain.contains("._tcp.") || domain.contains("._udp.")),
    }
}

pub async fn connect(raddr: &RemoteAddr, conn_opts: &ConnectOpts) -> Result<TcpStream> {
    let ConnectOpts {
        connect_timeout,
        bind_address,

        #[cfg(target_os = "linux")]
        bind_interface,
        ..
    } = conn_opts;

    let mut last_err = None;
    let keepalive = keepalive::build(conn_opts);

    log::info!("raddr======={}", raddr);
    if is_srv(raddr).await {
        //raddr解析srv转为host+端口的RemoteAddr
        let srv_raddr = resolve_srv(raddr).await;
        let new_raddr = &srv_raddr;
        for addr in resolve_addr(new_raddr).await?.iter() {
            log::debug!("[tcp]{} resolved as {}", raddr, &addr);
            let socket = new_tcp_socket(&addr)?;
    
            // ignore error
            let _ = socket.set_nodelay(true);
            let _ = socket.set_reuse_address(true);
    
            if let Some(addr) = *bind_address {
                socket.bind(&addr.into())?;
            }
    
            #[cfg(target_os = "linux")]
            if let Some(iface) = bind_interface {
                realm_syscall::bind_to_device(&socket, iface)?;
            }
    
            if let Some(kpa) = &keepalive {
                socket.set_tcp_keepalive(kpa)?;
            }
    
            let socket = TcpSocket::from_std_stream(socket.into());
    
            match timeoutfut(socket.connect(addr), *connect_timeout).await {
                Ok(Ok(stream)) => {
                    log::debug!("[tcp]connect to {} as {}", raddr, &addr,);
                    return Ok(stream);
                }
                Ok(Err(e)) => {
                    log::warn!("[tcp]connect to {} as {}: {}, try next ip", raddr, &addr, &e);
                    last_err = Some(e);
                }
                Err(_) => log::warn!("[tcp]connect to {} as {} timeout, try next ip", raddr, &addr),
            }
        }
    } else {
        for addr in resolve_addr(raddr).await?.iter() {
            log::debug!("[tcp]{} resolved as {}", raddr, &addr);
            let socket = new_tcp_socket(&addr)?;
    
            // ignore error
            let _ = socket.set_nodelay(true);
            let _ = socket.set_reuse_address(true);
    
            if let Some(addr) = *bind_address {
                socket.bind(&addr.into())?;
            }
    
            #[cfg(target_os = "linux")]
            if let Some(iface) = bind_interface {
                realm_syscall::bind_to_device(&socket, iface)?;
            }
    
            if let Some(kpa) = &keepalive {
                socket.set_tcp_keepalive(kpa)?;
            }
    
            let socket = TcpSocket::from_std_stream(socket.into());
    
            match timeoutfut(socket.connect(addr), *connect_timeout).await {
                Ok(Ok(stream)) => {
                    log::debug!("[tcp]connect to {} as {}", raddr, &addr,);
                    return Ok(stream);
                }
                Ok(Err(e)) => {
                    log::warn!("[tcp]connect to {} as {}: {}, try next ip", raddr, &addr, &e);
                    last_err = Some(e);
                }
                Err(_) => log::warn!("[tcp]connect to {} as {} timeout, try next ip", raddr, &addr),
            }
        }
    }
    

    Err(last_err.unwrap_or_else(|| Error::new(ErrorKind::InvalidInput, "could not connect to any address")))
}

pub(super) mod keepalive {
    use super::*;
    pub use realm_syscall::socket2::{SockRef, TcpKeepalive};
    pub fn build(conn_opts: &ConnectOpts) -> Option<TcpKeepalive> {
        let ConnectOpts {
            tcp_keepalive,
            tcp_keepalive_probe,
            ..
        } = conn_opts;
        if *tcp_keepalive == 0 {
            return None;
        };
        let secs = Duration::from_secs(*tcp_keepalive as u64);
        let mut kpa = TcpKeepalive::new().with_time(secs);
        #[cfg(not(target_os = "openbsd"))]
        {
            kpa = TcpKeepalive::with_interval(kpa, secs);
        }
        #[cfg(not(any(target_os = "openbsd", target_os = "windows")))]
        {
            let probe = *tcp_keepalive_probe as u32;
            kpa = TcpKeepalive::with_retries(kpa, probe);
        }

        Some(kpa)
    }
}
