//! Shared CLI and independently verified identity handling for signing examples.
//! This module checks identity fields; it does not verify Nitro COSE evidence.

use anyhow::{bail, ensure, Context, Result};
use bitcoin::bip32::Xpub;
use bitcoin::Network;
use sapio_tee::deployment::{program_profile, ProgramProfile, IDENTITY_PROTOCOL};
use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;

const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    protocol: String,
    mode: String,
    pub xpub: Xpub,
    settings: serde_json::Value,
    signing: ProgramProfile,
}

pub struct Options {
    pub address: SocketAddr,
    identity: PathBuf,
    allow_local_dev: bool,
}

pub fn options(example_name: &str) -> Result<Option<Options>> {
    let mut args = std::env::args_os().skip(1);
    let mut address = None;
    let mut identity = None;
    let mut allow_local_dev = false;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--help") => {
                println!(
                    "Usage: {example_name} --address IP:PORT --identity FILE [--allow-local-dev]\n\
                     FILE must be the exact identity JSON accepted by an independent Nitro\n\
                     attestation verifier, using independently trusted measurements and settings.\n\
                     This example does NOT verify COSE or trust/fetch /public-key.\n\
                     --allow-local-dev permits an unattested local-dev identity with null settings\n\
                     and a test-network xpub, solely for synthetic regtest fixtures.\n\
                     All funding is synthetic. Nothing is broadcast; no private keys are needed."
                );
                return Ok(None);
            }
            Some("--address") if address.is_none() => {
                let value = args.next().context("--address needs IP:PORT")?;
                address = Some(
                    value
                        .to_str()
                        .context("address must be UTF-8")?
                        .parse()
                        .context("address must be an explicit numeric SocketAddr")?,
                );
            }
            Some("--identity") if identity.is_none() => {
                identity = Some(PathBuf::from(args.next().context("--identity needs FILE")?));
            }
            Some("--allow-local-dev") if !allow_local_dev => allow_local_dev = true,
            _ => bail!("unknown or repeated argument: {argument:?}; use --help"),
        }
    }
    Ok(Some(Options {
        address: address.context("--address is required; use --help")?,
        identity: identity.context("--identity is required; use --help")?,
        allow_local_dev,
    }))
}

pub fn load_identity(options: &Options) -> Result<Identity> {
    let mut bytes = Vec::new();
    File::open(&options.identity)
        .context("opening identity file")?
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_IDENTITY_BYTES,
        "identity exceeds 64 KiB"
    );
    let identity: Identity = serde_json::from_slice(&bytes).context("parsing identity JSON")?;
    ensure!(
        identity.protocol == IDENTITY_PROTOCOL,
        "unsupported identity protocol"
    );
    ensure!(
        identity.signing == program_profile(),
        "identity has an unexpected program profile"
    );
    match identity.mode.as_str() {
        "nitro" => {
            ensure!(
                identity.settings.is_object(),
                "Nitro identity requires settings"
            );
        }
        "local-dev" if options.allow_local_dev => {
            ensure!(
                identity.settings.is_null(),
                "local-dev settings must be null"
            );
            ensure!(
                identity.xpub.network == Network::Regtest.into(),
                "local-dev requires a test-network xpub"
            );
            eprintln!(
                "WARNING: unattested local-dev identity; synthetic regtest demonstration only"
            );
        }
        _ => bail!("expected nitro identity (local-dev requires --allow-local-dev)"),
    }
    Ok(identity)
}
