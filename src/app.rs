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
    let router = Router::new()
        .route("/health", get(health))
        .route("/setup", post(setup))
        .route("/public-key", get(public_key))
        .route("/attestation", post(attestation))
        .nest("/ark", ark_routes)
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
