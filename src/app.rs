use crate::{keys::Settings, nsm::Nsm};
use anyhow::{anyhow, bail, Context, Result};
use ark::sapio::protocol::{
    CancelRequest, FinishRequest, FinishResponse, PrepareRequest, PrepareResponse, MAX_REQUEST_BYTES,
};
use axum::{
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, State},
    http::{header::CONTENT_TYPE, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    BoxError, Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::bip32::{Xpriv, Xpub};
use emulator_connect::program::ProgramOracle;
use sapio_tee::ark_signer::ArkSigner;
use sapio_tee::deployment::{
    program_oracle, program_profile, ProgramProfile, IDENTITY_PROTOCOL, MAX_CONNECTIONS,
    REQUEST_TIMEOUT_SECS,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex, Semaphore},
};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

const API_ADDRESS: &str = "127.0.0.1:8000";
const SIGNER_ADDRESS: &str = "127.0.0.1:8367";

#[derive(Serialize)]
struct Identity {
    protocol: &'static str,
    mode: &'static str,
    xpub: Xpub,
    settings: Option<Settings>,
    signing: ProgramProfile,
}

struct SignerJob {
    oracle: ProgramOracle,
    listener: TcpListener,
}

struct AppState {
    // A single JSON serialization is both served and hashed into attestation.
    identity: OnceLock<String>,
    ark_signer: OnceLock<Arc<ArkSigner>>,
    ark_admission: Arc<Semaphore>,
    setup_gate: Mutex<()>,
    work: mpsc::Sender<SignerJob>,
    nsm: Option<Nsm>,
}

impl AppState {
    async fn install(&self, root: Xpriv, settings: Option<Settings>) -> Result<()> {
        let oracle = program_oracle(root)?;
        let ark_signer = Arc::new(ArkSigner::new(root)?);
        let identity = serde_json::to_string(&Identity {
            protocol: IDENTITY_PROTOCOL,
            mode: if self.nsm.is_some() {
                "nitro"
            } else {
                "local-dev"
            },
            xpub: oracle.public_root(),
            settings,
            signing: program_profile(),
        })?;
        let listener = TcpListener::bind(SIGNER_ADDRESS).await?;
        let job = SignerJob { oracle, listener };
        // No await between handing off the key and publishing its identity:
        // cancellation cannot leave a half-initialized service.
        self.work
            .try_send(job)
            .map_err(|_| anyhow!("signer task unavailable"))?;
        self.ark_signer
            .set(ark_signer)
            .map_err(|_| anyhow!("Ark signer already initialized"))?;
        self.identity
            .set(identity)
            .map_err(|_| anyhow!("already initialized"))?;
        Ok(())
    }
}

type ApiError = (StatusCode, &'static str);

async fn setup(
    State(state): State<Arc<AppState>>,
    Json(settings): Json<Settings>,
) -> Result<Response, ApiError> {
    settings
        .validate()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid setup settings"))?;
    let _guard = state
        .setup_gate
        .try_lock()
        .map_err(|_| (StatusCode::CONFLICT, "setup already in progress"))?;
    if state.identity.get().is_some() {
        return Err((
            StatusCode::CONFLICT,
            "already initialized; restart to change identity",
        ));
    }
    if state.nsm.is_none() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Nitro provisioning unavailable",
        ));
    }
    let root = crate::keys::derive_root(&settings)
        .await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "attested KMS provisioning failed"))?;
    state
        .install(root, Some(settings))
        .await
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "could not start signer"))?;
    public_key(State(state.clone())).await
}

async fn public_key(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let identity = state
        .identity
        .get()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "not initialized"))?;
    Ok(([("content-type", "application/json")], identity.clone()).into_response())
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    if state.identity.get().is_some() {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not initialized").into_response()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationRequest {
    nonce: String,
}

#[derive(Serialize)]
struct AttestationResponse {
    identity_json: String,
    document: String,
}

async fn attestation(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AttestationRequest>,
) -> Result<Json<AttestationResponse>, ApiError> {
    let nonce = hex::decode(&request.nonce)
        .map_err(|_| (StatusCode::BAD_REQUEST, "nonce must be hexadecimal"))?;
    if !(16..=64).contains(&nonce.len()) {
        return Err((StatusCode::BAD_REQUEST, "nonce must contain 16..64 bytes"));
    }
    let identity = state
        .identity
        .get()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "not initialized"))?;
    let nsm = state
        .nsm
        .as_ref()
        .ok_or((StatusCode::SERVICE_UNAVAILABLE, "local-dev cannot attest"))?;
    let document = nsm
        .attest(nonce, identity.as_bytes())
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "NSM attestation failed"))?;
    Ok(Json(AttestationResponse {
        identity_json: identity.clone(),
        document: STANDARD.encode(document),
    }))
}

type ArkApiError = (StatusCode, String);

fn ark_signer(state: &AppState) -> Result<Arc<ArkSigner>, ArkApiError> {
    if state.identity.get().is_none() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "not initialized".into()));
    }
    state.ark_signer.get().cloned().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Ark signer unavailable".into())
    })
}

async fn ark_prepare(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PrepareRequest>,
) -> Result<Json<PrepareResponse>, ArkApiError> {
    let signer = ark_signer(&state)?;
    let permit = state.ark_admission.clone().try_acquire_owned().map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "program evaluation capacity exceeded".into())
    })?;
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        signer.prepare(request)
    }).await.map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "program evaluator unavailable".into())
    })?;
    result.map(Json).map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()))
}

async fn ark_finish(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FinishRequest>,
) -> Result<Json<FinishResponse>, ArkApiError> {
    ark_signer(&state)?.finish(request).map(Json)
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()))
}

async fn ark_cancel(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CancelRequest>,
) -> Result<StatusCode, ArkApiError> {
    ark_signer(&state)?.cancel(request)
        .map(|()| StatusCode::NO_CONTENT)
        .map_err(|error| (StatusCode::UNPROCESSABLE_ENTITY, error.to_string()))
}

/// Compose the public HTTP router. Every admitted request — header dispatch,
/// body extraction and handler work — must complete within `request_deadline`,
/// which runs inside the per-route concurrency permit: a stalled or trickled
/// body is dropped with 408 and its admission slot is released, so cheap
/// incomplete requests cannot pin an entire route. This mirrors the TCP
/// signer's REQUEST_TIMEOUT_SECS I/O deadline.
fn build_router(state: Arc<AppState>, request_deadline: std::time::Duration) -> Router {
    // Only the credential-free signing protocol is callable by browser wallets.
    // Setup and attestation retain their existing, non-CORS administrative surface.
    let ark_routes = Router::new()
        .route("/prepare", post(ark_prepare).layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES)))
        .route("/finish", post(ark_finish))
        .route("/cancel", post(ark_cancel))
        .layer(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([Method::POST])
            .allow_headers([CONTENT_TYPE]));
    Router::new()
        .route("/health", get(health))
        .route("/setup", post(setup))
        .route("/public-key", get(public_key))
        .route("/attestation", post(attestation))
        .nest("/ark", ark_routes)
        .layer(DefaultBodyLimit::max(4096))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        (StatusCode::REQUEST_TIMEOUT, "request deadline exceeded")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "API capacity exceeded")
                    }
                }))
                .layer(tower::timeout::TimeoutLayer::new(request_deadline))
                .load_shed()
                .concurrency_limit(16),
        )
        .with_state(state)
}

pub async fn run(nsm: Option<Nsm>) -> Result<()> {
    let (work, mut jobs) = mpsc::channel::<SignerJob>(1);
    let state = Arc::new(AppState {
        identity: OnceLock::new(),
        ark_signer: OnceLock::new(),
        ark_admission: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        setup_gate: Mutex::new(()),
        work,
        nsm,
    });

    #[cfg(feature = "local-dev")]
    if state.nsm.is_none() {
        use bitcoin::secp256k1::rand::{rngs::OsRng, RngCore};
        use zeroize::Zeroizing;
        let mut seed = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(seed.as_mut());
        let root = Xpriv::new_master(bitcoin::Network::Regtest, seed.as_ref())?;
        state.install(root, None).await?;
        eprintln!("WARNING: local-dev, ephemeral regtest key; NO enclave security or attestation");
    }

    let router = build_router(
        state,
        std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
    );
    let listener = TcpListener::bind(API_ADDRESS).await?;
    eprintln!("sapio-tee API listening on {API_ADDRESS}; ProgramOracle port {SIGNER_ADDRESS}");
    let signer = async move {
        let job = jobs
            .recv()
            .await
            .context("signer initialization channel closed")?;
        // Admission bounds concurrent requests, not native compilation wall time.
        job.oracle
            .serve_with_limits(
                job.listener,
                std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS),
                MAX_CONNECTIONS,
            )
            .await?;
        bail!("signer exited unexpectedly")
    };
    tokio::select! {
        result = axum::serve(listener, router) => { result?; bail!("API exited unexpectedly"); }
        result = signer => result,
        result = shutdown() => result,
    }
}

async fn shutdown() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result?,
        _ = terminate.recv() => {},
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Regression for the body-trickle denial of service: an admitted request whose
    /// body never completes must be rejected at the request deadline with 408, and
    /// the route must stay available to complete requests meanwhile.
    #[tokio::test]
    async fn stalled_body_is_rejected_at_the_request_deadline() -> Result<()> {
        let (work, _jobs) = mpsc::channel::<SignerJob>(1);
        let state = Arc::new(AppState {
            identity: OnceLock::new(),
            ark_signer: OnceLock::new(),
            ark_admission: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            setup_gate: Mutex::new(()),
            work,
            nsm: None,
        });
        let router = build_router(state, std::time::Duration::from_millis(100));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move { axum::serve(listener, router).await });

        // Complete headers declaring a 1024-byte body, then a single byte, held open.
        let mut stalled = tokio::net::TcpStream::connect(address).await?;
        stalled
            .write_all(b"POST /setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1024\r\n\r\n{")
            .await?;

        let mut response = vec![0u8; 4096];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stalled.read(&mut response),
        )
        .await
        .context("no response to a stalled body within 5s")??;
        let head = String::from_utf8_lossy(&response[..read]).into_owned();
        assert!(
            head.starts_with("HTTP/1.1 408"),
            "stalled body must be rejected at the deadline, got: {head:?}"
        );
        assert!(head.contains("request deadline exceeded"), "{head:?}");

        // A complete request on the same served router is unaffected.
        let mut live = tokio::net::TcpStream::connect(address).await?;
        live.write_all(
            b"POST /setup HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
        )
        .await?;
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            live.read(&mut response),
        )
        .await
        .context("no response to a complete request")??;
        let head = String::from_utf8_lossy(&response[..read]).into_owned();
        assert!(head.starts_with("HTTP/1.1 "), "{head:?}");
        assert!(!head.starts_with("HTTP/1.1 408"), "{head:?}");
        assert!(!head.starts_with("HTTP/1.1 503"), "{head:?}");

        server.abort();
        Ok(())
    }
}
