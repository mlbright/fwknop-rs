//! Finding the client's external IP address over HTTPS (`-R`).

use std::io::Read;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};

pub const DEFAULT_RESOLVE_URL: &str = "https://api.ipify.org";

/// Fetches `url` and returns the IP address in its body (at most 256 bytes,
/// surrounding whitespace ignored).
pub fn resolve_external_ip(url: &str) -> Result<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent
        .get(url)
        .call()
        .map_err(|e| anyhow!("resolving external IP: {e}"))?;
    let status = resp.status().as_u16();
    if status != 200 {
        bail!("IP resolution returned HTTP {status}");
    }
    let mut body = Vec::new();
    resp.body_mut()
        .as_reader()
        .take(256)
        .read_to_end(&mut body)
        .map_err(|e| anyhow!("reading IP resolution response: {e}"))?;
    let text = String::from_utf8_lossy(&body);
    let ip = text.trim();
    if ip.parse::<IpAddr>().is_err() {
        bail!("IP resolution returned invalid IP: {ip:?}");
    }
    Ok(ip.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    /// Serves one HTTP response on localhost and returns its URL.
    fn serve(status: &str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let status = status.to_string();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap() > 0 && line != "\r\n" {
                line.clear();
            }
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        format!("http://{addr}/")
    }

    #[test]
    fn returns_the_ip() {
        assert_eq!(
            resolve_external_ip(&serve("200 OK", "203.0.113.42")).unwrap(),
            "203.0.113.42"
        );
    }

    #[test]
    fn trims_whitespace() {
        assert_eq!(
            resolve_external_ip(&serve("200 OK", "  198.51.100.1\n")).unwrap(),
            "198.51.100.1"
        );
    }

    #[test]
    fn rejects_invalid_response() {
        let err = resolve_external_ip(&serve("200 OK", "not-an-ip")).unwrap_err();
        assert!(err.to_string().contains("invalid IP"), "{err}");
    }

    #[test]
    fn rejects_server_error() {
        let err = resolve_external_ip(&serve("500 Internal Server Error", "oops")).unwrap_err();
        assert!(err.to_string().contains("HTTP 500"), "{err}");
    }
}
