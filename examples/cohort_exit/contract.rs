//! Cohort Exit: all agreed payouts together, or the depositor's native refund.

use anyhow::{ensure, Result};
use bitcoin::{bip32::Xpub, ScriptBuf, XOnlyPublicKey};
use sapio_base::policy::ScriptPolicy;
use sapio_base::program::{EmulatedProgram, ProgramInstance};
use sapio_base::{timelocks::RelHeight, Clause};

pub const REFUND_BLOCKS: u16 = 144;
const WASM: &[u8] = include_bytes!("cohort_exit.wasm");

pub fn instance(
    nonce: [u8; 32],
    denomination: u64,
    fee_cap: u64,
    mut recipients: Vec<ScriptBuf>,
) -> Result<ProgramInstance> {
    ensure!(
        (2..=32).contains(&recipients.len()),
        "cohort size must be 2..=32"
    );
    ensure!(
        denomination <= 2_100_000_000_000_000,
        "invalid denomination"
    );
    ensure!(
        denomination.checked_sub(fee_cap).is_some_and(|v| v >= 330),
        "fee cap leaves dust"
    );
    recipients.sort_unstable();
    ensure!(recipients.iter().all(|s| s.is_p2tr()), "only P2TR payouts");
    ensure!(
        recipients.windows(2).all(|p| p[0] != p[1]),
        "duplicate payout"
    );
    let mut parameters = Vec::with_capacity(56 + recipients.len() * 34);
    parameters.extend_from_slice(b"CE01");
    parameters.extend_from_slice(&nonce);
    parameters.extend_from_slice(&(recipients.len() as u32).to_le_bytes());
    parameters.extend_from_slice(&denomination.to_le_bytes());
    parameters.extend_from_slice(&fee_cap.to_le_bytes());
    for script in recipients {
        parameters.extend_from_slice(script.as_bytes());
    }
    Ok(ProgramInstance::wasm(WASM.to_vec(), parameters)?)
}

pub struct CohortExit {
    emulation: EmulatedProgram,
    owner: XOnlyPublicKey,
}

#[sapio::contract]
impl CohortExit {
    pub fn new(instance: ProgramInstance, root: Xpub, owner: XOnlyPublicKey) -> Result<Self> {
        Ok(Self {
            emulation: EmulatedProgram::new(instance, root)?,
            owner,
        })
    }

    #[spend]
    fn settle(&self) -> ScriptPolicy {
        self.emulation.clone().into()
    }

    #[spend]
    fn refund(&self) -> Clause {
        Clause::And(vec![
            Clause::Key(self.owner).into(),
            Clause::try_from(RelHeight::from(REFUND_BLOCKS))
                .expect("nonzero constant refund delay")
                .into(),
        ])
    }
}
