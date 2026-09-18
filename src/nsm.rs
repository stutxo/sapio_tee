use anyhow::{bail, ensure, Result};
use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver::{nsm_exit, nsm_init, nsm_process_request},
};
use sha2::{Digest, Sha256};

/// No emulated attestation provider exists in the production binary.
pub struct Nsm(i32);

impl Nsm {
    pub fn open() -> Result<Self> {
        let fd = nsm_init();
        ensure!(
            fd >= 0,
            "Nitro NSM unavailable; production requires /dev/nsm"
        );
        let nsm = Self(fd);
        // Debug enclaves have zero measurements. Refuse them before provisioning.
        for index in 0..=2 {
            match nsm_process_request(fd, Request::DescribePCR { index }) {
                Response::DescribePCR { lock, data }
                    if lock && data.len() == 48 && data.iter().any(|byte| *byte != 0) => {}
                _ => bail!(
                    "PCR{index} must be locked, nonzero SHA-384; debug enclaves are forbidden"
                ),
            }
        }
        Ok(nsm)
    }

    pub fn attest(&self, nonce: Vec<u8>, identity_json: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            (16..=64).contains(&nonce.len()),
            "nonce must contain 16..64 bytes"
        );
        match nsm_process_request(
            self.0,
            Request::Attestation {
                nonce: Some(nonce.into()),
                user_data: Some(Sha256::digest(identity_json).to_vec().into()),
                public_key: None,
            },
        ) {
            Response::Attestation { document } => Ok(document),
            _ => bail!("NSM attestation failed"),
        }
    }
}

impl Drop for Nsm {
    fn drop(&mut self) {
        nsm_exit(self.0);
    }
}
