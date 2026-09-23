use anyhow::{bail, ensure, Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Backend {
    #[default]
    Substrate,
    Arkworks,
    Mcl,
}

impl Backend {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "substrate" => Ok(Self::Substrate),
            "arkworks" => Ok(Self::Arkworks),
            "mcl" => Ok(Self::Mcl),
            _ => bail!("unknown backend {value:?}; expected substrate, arkworks or mcl"),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Substrate => "substrate",
            Self::Arkworks => "arkworks",
            Self::Mcl => "mcl",
        }
    }

    pub fn reference_description(self) -> &'static str {
        match self {
            Self::Substrate => "native arkworks reference (independent arithmetic from substrate guest)",
            Self::Arkworks => "native arkworks reference (same arithmetic library as arkworks guest; not independent)",
            Self::Mcl => "native arkworks reference (independent arithmetic from MCL guest)",
        }
    }

    pub fn prepare_parameters(self, raw: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Substrate => crate::prepared::prepare_parameters(raw),
            Self::Arkworks => {
                checkzkp_ark_guest::prepare_parameters(raw).map_err(anyhow::Error::msg)
            }
            Self::Mcl => prepare_mcl(raw),
        }
    }
}

// Fixed-key preparation only: the child receives no proof or transaction.
fn prepare_mcl(raw: &[u8]) -> Result<Vec<u8>> {
    let executable = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/mcl-comparison/prepare");
    let mut child = Command::new(&executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "starting {}; run experiments/op_checkzkp/build-mcl.sh first",
                executable.display()
            )
        })?;
    let written = child
        .stdin
        .take()
        .context("MCL preparation stdin")?
        .write_all(raw);
    let output = child
        .wait_with_output()
        .context("waiting for MCL preparation")?;
    ensure!(
        output.status.success(),
        "MCL preparation failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    written.context("writing MCL source parameters")?;
    Ok(output.stdout)
}
