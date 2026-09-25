//! Native driver for the exact browser wallet JSON operations.
//! Reads one public-only Call from stdin, prints its result, and never broadcasts.
//! --oracle ADDRESS sends a `request` operation to an actual ProgramOracle and
//! runs the browser core's independent response verification and finalization.

#[cfg(test)]
mod recovery_tests;
#[cfg(test)]
mod tests;

use anyhow::{anyhow, ensure, Context, Result};
use emulator_connect::program::{ProgramClient, ProgramSigningRequest, PSBT};
use passkey_client::{
    wire::{OracleRequest, OracleResponse, WirePsbt},
    Call, CAPACITY,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::SocketAddr;

async fn run(input: &[u8], oracle: Option<SocketAddr>) -> Result<Value> {
    let call: Call = serde_json::from_slice(input).context("invalid wallet Call JSON")?;
    let Some(address) = oracle else {
        return passkey_client::call(call);
    };
    ensure!(
        call.operation == "request",
        "--oracle requires a request operation with the approved WebAuthn assertion"
    );
    let context = call.context.clone();
    // Validate the pinned identity, instance, PSBT and assertion framing before
    // performing any transport action. Never discover a new root over the wire.
    let request = passkey_client::call(call)?;
    let OracleRequest::SignProgramV1(body) = serde_json::from_value(request.clone())?;
    let native = ProgramSigningRequest {
        instance: body.instance,
        input_index: body.input_index,
        witness: body.witness,
        path: body.path,
        psbt: PSBT(body.psbt.0),
    };
    let client = ProgramClient::new(address, context.identity.xpub)?;
    let signed = client.sign(native).await?;
    passkey_client::call(Call {
        operation: "finalize_passkey".into(),
        context,
        body: json!({"request": request, "response": OracleResponse::SignedV1(WirePsbt(signed))}),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut oracle = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--oracle" => {
                ensure!(oracle.is_none(), "--oracle may appear only once");
                oracle = Some(
                    args.next()
                        .context("--oracle requires HOST:PORT")?
                        .parse()?,
                );
            }
            "--help" | "-h" => {
                println!("passkey [--oracle IP:PORT]\nRead one browser wallet JSON Call from stdin; write {{ok:...}} or {{error:...}}.\nWithout --oracle every operation is offline. With --oracle, a request is signed by the pinned ProgramOracle and independently finalized. No broadcast.\nCall: {{operation,context:{{identity,origin,rp_id,allow_local_dev}},body}}");
                return Ok(());
            }
            _ => return Err(anyhow!("unknown argument; use --help")),
        }
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(CAPACITY as u64 + 1)
        .read_to_end(&mut input)?;
    let result = if input.is_empty() || input.len() > CAPACITY {
        Err(anyhow!("invalid wallet input length"))
    } else {
        run(&input, oracle).await
    };
    let envelope = match result {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"error": format!("{error:#}")}),
    };
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &envelope)?;
    writeln!(output)?;
    Ok(())
}
