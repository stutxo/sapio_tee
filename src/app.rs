use crate::{keys::Settings, nsm::Nsm};
use anyhow::{anyhow, bail, Context, Result};
use axum::{
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    BoxError, Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bitcoin::bip32::{Xpriv, Xpub};
use emulator_connect::program::ProgramOracle;
use sapio_tee::deployment::{
    program_oracle, program_profile, ProgramProfile, IDENTITY_PROTOCOL, MAX_CONNECTIONS,
    REQUEST_TIMEOUT_SECS,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use tokio::{
    net::TcpListener,
    sync::{mpsc, Mutex},
};
use tower::ServiceBuilder;

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
    setup_gate: Mutex<()>,
    work: mpsc::Sender<SignerJob>,
    nsm: Option<Nsm>,
}

impl AppState {
    async fn install(&self, root: Xpriv, settings: Option<Settings>) -> Result<()> {
        let oracle = program_oracle(root)?;
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

pub async fn run(nsm: Option<Nsm>) -> Result<()> {
    let (work, mut jobs) = mpsc::channel::<SignerJob>(1);
    let state = Arc::new(AppState {
        identity: OnceLock::new(),
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

    let router = Router::new()
        .route("/health", get(health))
        .route("/setup", post(setup))
        .route("/public-key", get(public_key))
        .route("/attestation", post(attestation))
        .layer(DefaultBodyLimit::max(4096))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async {
                    (StatusCode::SERVICE_UNAVAILABLE, "API capacity exceeded")
                }))
                .load_shed()
                .concurrency_limit(16),
        )
        .with_state(state);
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
