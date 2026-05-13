//! Integration tests for WebSocket passthrough (PR 5 of #94).
//!
//! Spins up a real WebSocket upstream via `tokio-tungstenite::accept_async`
//! and exercises the passthrough handler end-to-end. Tests close-frame
//! propagation, bidirectional message flow, header injection, and
//! the `forward_websockets = false` default (where upgrades fall back
//! to plain HTTP and the upstream rejects).

use ati::core::auth_generator::AuthCache;
use ati::core::keyring::Keyring;
use ati::core::manifest::ManifestRegistry;
use ati::core::passthrough::PassthroughRouter;
use ati::core::skill::SkillRegistry;
use ati::proxy::server::{build_router, ProxyState};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn env_mutex() -> &'static std::sync::Mutex<()> {
    static M: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build a router with one passthrough manifest pointing at `upstream_url`
/// and `forward_websockets` set per the flag. Binds the router on a
/// random port and returns the bound address.
async fn spawn_proxy(
    upstream_url: &str,
    forward_websockets: bool,
    inject_header: Option<(&str, &str)>,
) -> SocketAddr {
    let dir = TempDir::new().unwrap();
    let manifests = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    let extra = match inject_header {
        Some((name, key)) => format!(
            r#"auth_type = "header"
auth_header_name = "{name}"
auth_key_name = "{key}"
"#
        ),
        None => String::new(),
    };
    std::fs::write(
        manifests.join("ws.toml"),
        format!(
            r#"
[provider]
name = "ws-test"
description = "ws test"
handler = "passthrough"
base_url = "{upstream_url}"
path_prefix = "/api"
forward_websockets = {forward_websockets}
{extra}
"#
        ),
    )
    .unwrap();

    // Keyring with the injected-header secret, if any.
    let keyring = if let Some((_, key)) = inject_header {
        let _guard = env_mutex().lock().unwrap_or_else(|p| p.into_inner());
        let var = format!("ATI_KEY_{}", key.to_uppercase());
        std::env::set_var(&var, "WS-SECRET");
        let kr = Keyring::from_env();
        std::env::remove_var(&var);
        kr
    } else {
        Keyring::empty()
    };

    let registry = ManifestRegistry::load(&manifests).expect("load");
    let passthrough = PassthroughRouter::build(&registry, &keyring).expect("router");
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough: Some(Arc::new(passthrough)),
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &Keyring::empty(),
            )
            .unwrap(),
        ),
    });
    let app = build_router(state);
    // Leak the tempdir so it lives for the duration of the test.
    std::mem::forget(dir);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Start a tiny echo WebSocket server. Returns the bound address and a
/// JoinHandle so the test can keep it alive.
async fn spawn_echo_upstream(
    expected_header: Option<(&'static str, &'static str)>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                // Capture the incoming headers via callback so we can
                // assert on header injection.
                use tokio_tungstenite::tungstenite::http::HeaderMap;
                let mut captured: Option<HeaderMap> = None;
                let captured_ref = &mut captured;
                #[allow(clippy::result_large_err)] // tungstenite callback shape
                let ws = tokio_tungstenite::accept_hdr_async(
                    stream,
                    |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                     resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                        *captured_ref = Some(req.headers().clone());
                        Ok(resp)
                    },
                )
                .await;
                let ws = match ws {
                    Ok(w) => w,
                    Err(_) => return,
                };
                // Assert injected header is present (test-time check).
                if let Some((name, value)) = expected_header {
                    let got = captured
                        .as_ref()
                        .and_then(|h| h.get(name))
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    assert_eq!(
                        got, value,
                        "upstream expected header {name}={value} but got {got:?}"
                    );
                }
                let (mut tx, mut rx) = ws.split();
                while let Some(Ok(msg)) = rx.next().await {
                    use tokio_tungstenite::tungstenite::Message;
                    match msg {
                        Message::Text(s) => {
                            let _ = tx.send(Message::Text(format!("echo:{s}"))).await;
                        }
                        Message::Binary(b) => {
                            let _ = tx.send(Message::Binary(b)).await;
                        }
                        Message::Close(c) => {
                            let _ = tx.send(Message::Close(c)).await;
                            break;
                        }
                        Message::Ping(p) => {
                            let _ = tx.send(Message::Pong(p)).await;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    (addr, handle)
}

#[tokio::test]
async fn ws_passthrough_echoes_text_frames_end_to_end() {
    let (upstream_addr, _upstream) = spawn_echo_upstream(None).await;
    let upstream_url = format!("http://{upstream_addr}");
    let proxy_addr = spawn_proxy(&upstream_url, true, None).await;

    // Client connects to the proxy at ws://proxy/api/anything — proxy
    // strips /api and opens a WS to upstream at /anything.
    let client_url = format!("ws://{proxy_addr}/api/x");
    let (mut client, _) = tokio_tungstenite::connect_async(&client_url)
        .await
        .expect("client connect");

    use tokio_tungstenite::tungstenite::Message;
    client.send(Message::Text("hello".into())).await.unwrap();
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), client.next())
        .await
        .expect("timeout")
        .expect("stream not closed")
        .expect("frame received");
    match echoed {
        Message::Text(t) => assert_eq!(t.as_str(), "echo:hello"),
        other => panic!("expected text echo, got {other:?}"),
    }
    client.send(Message::Close(None)).await.unwrap();
}

#[tokio::test]
async fn ws_passthrough_injects_auth_header_to_upstream() {
    // Auth header is resolved from the keyring at startup and inserted on
    // the WS upstream handshake (Greptile flagged this in PR 1 for HTTP;
    // the WS path needs the same behavior).
    let (upstream_addr, _upstream) = spawn_echo_upstream(Some(("x-bb-api-key", "WS-SECRET"))).await;
    let upstream_url = format!("http://{upstream_addr}");
    let proxy_addr = spawn_proxy(
        &upstream_url,
        true,
        Some(("x-bb-api-key", "browserbase_api_key")),
    )
    .await;

    let client_url = format!("ws://{proxy_addr}/api/x");
    let (mut client, _) = tokio_tungstenite::connect_async(&client_url)
        .await
        .expect("client connect");
    use tokio_tungstenite::tungstenite::Message;
    client.send(Message::Text("ping".into())).await.unwrap();
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), client.next())
        .await
        .expect("timeout")
        .expect("stream not closed")
        .expect("frame received");
    // The upstream's accept_hdr_async callback panics if the header
    // doesn't match; if we got an echoed frame here, the assertion
    // inside the upstream passed.
    match echoed {
        Message::Text(t) => assert_eq!(t.as_str(), "echo:ping"),
        other => panic!("expected text, got {other:?}"),
    }
    client.send(Message::Close(None)).await.unwrap();
}

#[tokio::test]
async fn ws_passthrough_disabled_when_forward_websockets_false() {
    // forward_websockets = false → the proxy treats the WS upgrade as
    // ordinary HTTP. tokio-tungstenite's connect_async then fails because
    // the response isn't a proper WS handshake.
    let (upstream_addr, _upstream) = spawn_echo_upstream(None).await;
    let upstream_url = format!("http://{upstream_addr}");
    let proxy_addr = spawn_proxy(&upstream_url, false, None).await;

    let client_url = format!("ws://{proxy_addr}/api/x");
    let res = tokio_tungstenite::connect_async(&client_url).await;
    assert!(
        res.is_err(),
        "with forward_websockets=false, the WS handshake must NOT succeed; got: {res:?}"
    );
}

#[tokio::test]
async fn ws_passthrough_propagates_binary_frames() {
    let (upstream_addr, _upstream) = spawn_echo_upstream(None).await;
    let upstream_url = format!("http://{upstream_addr}");
    let proxy_addr = spawn_proxy(&upstream_url, true, None).await;

    let client_url = format!("ws://{proxy_addr}/api/x");
    let (mut client, _) = tokio_tungstenite::connect_async(&client_url)
        .await
        .expect("client connect");

    use tokio_tungstenite::tungstenite::Message;
    let payload = vec![0u8, 1, 2, 3, 0xff];
    client.send(Message::Binary(payload.clone())).await.unwrap();
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), client.next())
        .await
        .expect("timeout")
        .expect("stream not closed")
        .expect("frame received");
    match echoed {
        Message::Binary(b) => assert_eq!(b.to_vec(), payload),
        other => panic!("expected binary echo, got {other:?}"),
    }
    client.send(Message::Close(None)).await.unwrap();
}

#[tokio::test]
async fn ws_passthrough_injects_auth_query_into_upstream_url() {
    // Greptile P1 on PR #98: routes with auth_type = "query" used to
    // silently lose the credential in the WS path because pump_ws only
    // injected header-style auth.
    use std::sync::Mutex;
    let captured_query: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_query_clone = captured_query.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let _upstream = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let captured = captured_query_clone.clone();
            tokio::spawn(async move {
                #[allow(clippy::result_large_err)]
                let ws = tokio_tungstenite::accept_hdr_async(
                    stream,
                    |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                     resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                        let uri = req.uri();
                        *captured.lock().unwrap() = uri.query().map(String::from);
                        Ok(resp)
                    },
                )
                .await;
                if let Ok(ws) = ws {
                    let (mut tx, _) = ws.split();
                    let _ = tx
                        .send(tokio_tungstenite::tungstenite::Message::Text("ok".into()))
                        .await;
                }
            });
        }
    });

    // Manifest with auth_type = "query"
    let dir = TempDir::new().unwrap();
    let manifests = dir.path().join("manifests");
    std::fs::create_dir_all(&manifests).unwrap();
    std::fs::write(
        manifests.join("ws.toml"),
        format!(
            r#"
[provider]
name = "ws-q"
description = "t"
handler = "passthrough"
base_url = "http://{upstream_addr}"
path_prefix = "/api"
forward_websockets = true
auth_type = "query"
auth_query_name = "token"
auth_key_name = "ws_query_secret"
"#
        ),
    )
    .unwrap();

    let keyring = {
        let _guard = env_mutex().lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("ATI_KEY_WS_QUERY_SECRET", "tok 123/with&punct");
        let kr = Keyring::from_env();
        std::env::remove_var("ATI_KEY_WS_QUERY_SECRET");
        kr
    };

    let registry = ManifestRegistry::load(&manifests).unwrap();
    let passthrough = PassthroughRouter::build(&registry, &keyring).unwrap();
    let skill_registry = SkillRegistry::load(std::path::Path::new("/nonexistent")).unwrap();
    let state = Arc::new(ProxyState {
        registry,
        skill_registry,
        keyring,
        jwt_config: None,
        jwks_json: None,
        auth_cache: AuthCache::new(),
        db: ati::core::db::DbState::Disabled,
        passthrough: Some(Arc::new(passthrough)),
        sig_verify: std::sync::Arc::new(
            ati::core::sig_verify::SigVerifyConfig::build(
                ati::core::sig_verify::SigVerifyMode::Log,
                60,
                ati::core::sig_verify::DEFAULT_EXEMPT_PATHS,
                &Keyring::empty(),
            )
            .unwrap(),
        ),
    });
    let app = build_router(state);
    std::mem::forget(dir);
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(proxy_listener, app).await;
    });

    let client_url = format!("ws://{proxy_addr}/api/x");
    let (mut client, _) = tokio_tungstenite::connect_async(&client_url)
        .await
        .expect("client connect");
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), client.next()).await;
    let _ = client
        .send(tokio_tungstenite::tungstenite::Message::Close(None))
        .await;

    let q = captured_query.lock().unwrap().clone();
    assert!(
        q.as_deref()
            .is_some_and(|s| s.contains("token=tok%20123%2Fwith%26punct")),
        "upstream URL must include percent-encoded token query param; got: {q:?}"
    );
}

#[tokio::test]
async fn ws_passthrough_forwards_subprotocol_header() {
    // Greptile P2 on PR #98: client headers were dropped by passing
    // `req` directly to WebSocketUpgrade::from_request. Now we extract
    // and forward Sec-WebSocket-Protocol so subprotocol-aware upstreams
    // can negotiate.
    use std::sync::Mutex;
    let captured_proto: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured_proto.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let _upstream = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let captured = captured_clone.clone();
            tokio::spawn(async move {
                #[allow(clippy::result_large_err)]
                let ws = tokio_tungstenite::accept_hdr_async(
                    stream,
                    |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                     mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                        let proto = req
                            .headers()
                            .get("sec-websocket-protocol")
                            .and_then(|v| v.to_str().ok())
                            .map(String::from);
                        // Echo the protocol back so the client's strict
                        // handshake validator accepts the response.
                        if let Some(ref p) = proto {
                            if let Ok(v) =
                                tokio_tungstenite::tungstenite::http::HeaderValue::from_str(p)
                            {
                                resp.headers_mut().insert("sec-websocket-protocol", v);
                            }
                        }
                        *captured.lock().unwrap() = proto;
                        Ok(resp)
                    },
                )
                .await;
                if let Ok(ws) = ws {
                    let (mut tx, _) = ws.split();
                    let _ = tx
                        .send(tokio_tungstenite::tungstenite::Message::Text("ok".into()))
                        .await;
                }
            });
        }
    });

    let upstream_url = format!("http://{upstream_addr}");
    let proxy_addr = spawn_proxy(&upstream_url, true, None).await;

    // We only need to verify the upstream RECEIVED the header. The
    // client-side subprotocol echo back through axum is a separate
    // axum concern (subprotocol negotiation requires `WebSocketUpgrade::
    // protocols()` to be wired with the offered list; that's a
    // follow-up). For now: send the handshake, ignore whether the
    // client-side strict handshake validator complains, and check
    // captured_proto on the upstream side after a short grace period.
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut full = format!("ws://{proxy_addr}/api/x")
        .into_client_request()
        .unwrap();
    full.headers_mut().insert(
        "sec-websocket-protocol",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_static("graphql-transport-ws"),
    );
    // Don't unwrap — the client may legitimately reject the response
    // because axum doesn't echo subprotocols today. We only care that
    // the upstream saw the header before the handshake fails.
    let _ = tokio_tungstenite::connect_async(full).await;

    // Give the upstream a moment to record the captured header.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let proto = captured_proto.lock().unwrap().clone();
    assert_eq!(
        proto.as_deref(),
        Some("graphql-transport-ws"),
        "upstream must see the client's Sec-WebSocket-Protocol; got: {proto:?}"
    );
}

#[tokio::test]
async fn ws_passthrough_propagates_close_frame() {
    let (upstream_addr, _upstream) = spawn_echo_upstream(None).await;
    let upstream_url = format!("http://{upstream_addr}");
    let proxy_addr = spawn_proxy(&upstream_url, true, None).await;

    let client_url = format!("ws://{proxy_addr}/api/x");
    let (mut client, _) = tokio_tungstenite::connect_async(&client_url)
        .await
        .expect("client connect");
    use tokio_tungstenite::tungstenite::protocol::CloseFrame;
    use tokio_tungstenite::tungstenite::Message;
    client
        .send(Message::Close(Some(CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "bye".into(),
        })))
        .await
        .unwrap();
    // We expect either the echo of our close frame OR a clean stream end.
    // Both are valid "the close propagated" signals.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), client.next()).await;
    match result {
        Ok(Some(Ok(Message::Close(_)))) => {}
        Ok(None) => {}         // stream cleanly closed
        Ok(Some(Err(_))) => {} // upstream-driven close manifested as an error — also acceptable
        Ok(Some(Ok(other))) => panic!("expected Close, got {other:?}"),
        Err(_) => panic!("client never observed close propagation"),
    }
}
