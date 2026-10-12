//! XNet sockets, System Link LAN discovery, custom lobby client.
//!
//! LAN beacon/discovery is real UDP. Custom lobby is a minimal async
//! HTTP client against a configurable endpoint (not-started until a
//! server is configured; LAN-only when empty).

use std::net::SocketAddr;
use x360_common::{EmuError, Result};

pub const SYSTEMLINK_PORT: u16 = 3074;

/// Local player identity. Generated locally, never a console certificate.
#[derive(Debug, Clone)]
pub struct PlayerIdentity {
    pub xuid: u64,
    pub name: String,
}

impl PlayerIdentity {
    pub fn generate(name: &str) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        name.hash(&mut h);
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        t.hash(&mut h);
        let xuid = 0xE000_0000_0000_0000 | (h.finish() & 0x0000_FFFF_FFFF_FFFF);
        Self {
            xuid,
            name: name.to_string(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub host: String,
    pub game: String,
    pub players: u32,
    pub max_players: u32,
}

/// UDP bridge for XSocket send/recv. Real sockets, testable on loopback.
pub struct UdpBridge {
    sock: std::net::UdpSocket,
}

impl UdpBridge {
    pub fn bind(addr: &str) -> Result<Self> {
        let sock = std::net::UdpSocket::bind(addr).map_err(|e| EmuError::Network(e.to_string()))?;
        sock.set_nonblocking(true)
            .map_err(|e| EmuError::Network(e.to_string()))?;
        Ok(Self { sock })
    }

    pub fn send_to(&self, data: &[u8], target: &str) -> Result<usize> {
        let n = self
            .sock
            .send_to(data, target)
            .map_err(|e| EmuError::Network(e.to_string()))?;
        Ok(n)
    }

    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.sock
            .recv_from(buf)
            .map_err(|e| EmuError::Network(e.to_string()))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.sock
            .local_addr()
            .map_err(|e| EmuError::Network(e.to_string()))
    }

    /// Broadcast a System Link discovery beacon for a session.
    pub fn send_beacon(&self, session: &SessionInfo, target: &str) -> Result<usize> {
        let payload = serde_json::to_vec(session).map_err(|e| EmuError::Network(e.to_string()))?;
        let mut packet = b"X360SL".to_vec();
        packet.extend_from_slice(&payload);
        self.send_to(&packet, target)
    }

    /// Try to receive one beacon. Returns session + sender on success.
    pub fn recv_beacon(&self, buf: &mut [u8]) -> Result<(SessionInfo, SocketAddr)> {
        let (n, addr) = self.recv(buf)?;
        if n < 6 || &buf[..6] != b"X360SL" {
            return Err(EmuError::Network("not a System Link beacon".into()));
        }
        let session: SessionInfo = serde_json::from_slice(&buf[6..n])
            .map_err(|e| EmuError::Network(format!("bad beacon: {}", e)))?;
        Ok((session, addr))
    }
}

/// Session events for logging/diagnostics.
#[derive(Debug, Clone)]
pub enum NetEvent {
    SessionCreated { id: String },
    Discovered { addr: SocketAddr, game: String },
    Joined { id: String },
    Left { id: String },
    TransportError { msg: String },
    Packet { dir: String, len: usize },
}

impl NetEvent {
    pub fn log(&self) -> String {
        match self {
            NetEvent::SessionCreated { id } => format!("session created {}", id),
            NetEvent::Discovered { addr, game } => format!("discovered {} @{}", game, addr),
            NetEvent::Joined { id } => format!("joined {}", id),
            NetEvent::Left { id } => format!("left {}", id),
            NetEvent::TransportError { msg } => format!("transport error: {}", msg),
            NetEvent::Packet { dir, len } => format!("packet {} {}b", dir, len),
        }
    }
}

/// Minimal async lobby client. Uses the configured endpoint; empty
/// endpoint means LAN-only and returns explicit Unsupported.
pub struct LobbyClient {
    pub endpoint: String,
}

impl LobbyClient {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
        }
    }

    /// Health check against `GET {endpoint}/health` with timeout.
    /// http only; https is explicitly rejected (no TLS in M4).
    pub async fn health(&self) -> Result<String> {
        if self.endpoint.is_empty() {
            return Err(EmuError::Unsupported(
                "lobby not configured (LAN-only)".into(),
            ));
        }
        if self.endpoint.starts_with("https://") {
            return Err(EmuError::Unsupported(
                "https lobby not supported (http only)".into(),
            ));
        }
        if !self.endpoint.starts_with("http://") {
            return Err(EmuError::Network("lobby endpoint must be http://".into()));
        }
        let url = format!("{}/health", self.endpoint.trim_end_matches('/'));
        // Minimal HTTP over tokio TCP (http only, no TLS here).
        let addr = url
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("");
        if addr.is_empty() {
            return Err(EmuError::Network("bad lobby endpoint".into()));
        }
        let connect = tokio::net::TcpStream::connect(addr);
        let mut stream = tokio::time::timeout(std::time::Duration::from_secs(3), connect)
            .await
            .map_err(|_| EmuError::Network("lobby connect timeout".into()))?
            .map_err(|e| EmuError::Network(e.to_string()))?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let req = format!("GET /health HTTP/1.0\r\nHost: {}\r\n\r\n", addr);
        let write = stream.write_all(req.as_bytes());
        tokio::time::timeout(std::time::Duration::from_secs(3), write)
            .await
            .map_err(|_| EmuError::Network("lobby write timeout".into()))?
            .map_err(|e| EmuError::Network(e.to_string()))?;
        let mut buf = vec![0u8; 1024];
        let read = stream.read(&mut buf);
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), read)
            .await
            .map_err(|_| EmuError::Network("lobby read timeout".into()))?
            .map_err(|e| EmuError::Network(e.to_string()))?;
        Ok(String::from_utf8_lossy(&buf[..n]).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_is_local_range() {
        let id = PlayerIdentity::generate("player1");
        assert!((id.xuid & 0xFFFF_0000_0000_0000) == 0xE000_0000_0000_0000);
    }
    #[test]
    fn udp_loopback() {
        let a = UdpBridge::bind("127.0.0.1:0").unwrap();
        let b = UdpBridge::bind("127.0.0.1:0").unwrap();
        let ba = b.local_addr().unwrap().to_string();
        a.send_to(b"hello", &ba).unwrap();
        let mut buf = [0u8; 16];
        let mut got = None;
        for _ in 0..50 {
            match b.recv(&mut buf) {
                Ok((n, addr)) => {
                    got = Some((n, addr));
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        let (n, _) = got.expect("loopback packet");
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn beacon_discovery_between_instances() {
        let a = UdpBridge::bind("127.0.0.1:0").unwrap();
        let b = UdpBridge::bind("127.0.0.1:0").unwrap();
        let ba = b.local_addr().unwrap().to_string();
        let session = SessionInfo {
            id: "test-session".into(),
            host: "a".into(),
            game: "test-game".into(),
            players: 1,
            max_players: 4,
        };
        a.send_beacon(&session, &ba).unwrap();
        let mut buf = [0u8; 1024];
        let mut got = None;
        for _ in 0..50 {
            match b.recv_beacon(&mut buf) {
                Ok((s, addr)) => {
                    got = Some((s, addr));
                    break;
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        let (s, _) = got.expect("beacon");
        assert_eq!(s.id, "test-session");
        assert_eq!(s.game, "test-game");
        let ev = NetEvent::Discovered {
            addr: "127.0.0.1:3074".parse().unwrap(),
            game: s.game.clone(),
        };
        assert!(ev.log().contains("discovered"));
        assert_eq!(SYSTEMLINK_PORT, 3074);
    }

    #[tokio::test]
    async fn lobby_empty_is_explicit() {
        let c = LobbyClient::new("");
        assert!(c.health().await.is_err());
    }

    #[tokio::test]
    async fn lobby_https_is_explicit() {
        let c = LobbyClient::new("https://example.com");
        let err = c.health().await.unwrap_err().to_string();
        assert!(err.contains("https"));
    }

    #[tokio::test]
    async fn lobby_configured_health() {
        // Local TCP stub speaking minimal HTTP.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 512];
            let _ = sock.read(&mut buf).await;
            let _ = sock
                .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
        });
        let c = LobbyClient::new(&format!("http://{}", addr));
        let body = c.health().await.unwrap();
        assert!(body.contains("ok"));
        let _ = server.await;
    }
}
