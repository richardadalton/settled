use anyhow::Context;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Parser)]
#[command(about = "settled-check — verify Settled audit log proofs")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch and verify the latest STH from a Settled server.
    Verify {
        /// gRPC endpoint of the Settled server (e.g. http://localhost:50051)
        #[arg(long)]
        server: String,

        /// Also verify an inclusion proof for this entry sequence number
        #[arg(long)]
        seq: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    match args.command {
        Command::Verify { server, seq } => {
            cmd_verify(&server, seq).await?;
        }
    }

    Ok(())
}

async fn cmd_verify(server: &str, seq: Option<u64>) -> anyhow::Result<()> {
    let mut client = settled_client::SettledClient::connect(server.to_owned())
        .await
        .context("Failed to connect to Settled server")?;

    // Fetch the latest STH (tree_size=0 means "latest").
    let sth_resp = client
        .get_sth(0)
        .await
        .context("Failed to fetch latest STH")?;

    let sth = sth_resp.sth.context("Server returned no STH")?;

    println!("Latest STH:");
    println!("  tree_size  : {}", sth.tree_size);
    println!("  root_hash  : {}", hex::encode(&sth.root_hash));
    println!("  timestamp  : {} ns", sth.timestamp_ns);

    // Verify the STH Ed25519 signature.
    let pub_key_arr: [u8; 32] = sth
        .public_key
        .as_slice()
        .try_into()
        .context("public_key must be 32 bytes")?;
    let root_arr: [u8; 32] = sth
        .root_hash
        .as_slice()
        .try_into()
        .context("root_hash must be 32 bytes")?;
    let sig_arr: [u8; 64] = sth
        .signature
        .as_slice()
        .try_into()
        .context("signature must be 64 bytes")?;
    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_arr).context("Invalid Ed25519 public key")?;
    let signature = Signature::from_bytes(&sig_arr);

    if !settled_client::verify_tree_head(
        &verifying_key,
        sth.tree_size,
        &root_arr,
        sth.timestamp_ns,
        &signature,
    ) {
        anyhow::bail!("STH signature verification FAILED");
    }
    println!("  signature  : OK");

    if let Some(seq_num) = seq {
        // Fetch inclusion proof against the latest tree.
        let proof_resp = client
            .inclusion_proof(seq_num, sth.tree_size)
            .await
            .context("Failed to fetch inclusion proof")?;

        let proof_hashes: Vec<[u8; 32]> = proof_resp
            .proof
            .iter()
            .map(|h| {
                h.as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("proof node must be 32 bytes"))
            })
            .collect::<anyhow::Result<_>>()?;

        // The leaf hash for a log entry is SHA-256(0x00 || data).
        // We don't have the raw data here; instead we re-fetch the entry.
        let entry_resp = client.get(seq_num).await.context("Failed to fetch entry")?;

        let entry = entry_resp.entry.context("Server returned no entry")?;
        let leaf: [u8; 32] = entry
            .leaf_hash
            .as_slice()
            .try_into()
            .context("leaf_hash must be 32 bytes")?;

        if settled_client::verify_inclusion(
            &leaf,
            proof_resp.leaf_index,
            sth.tree_size,
            &proof_hashes,
            &root_arr,
        ) {
            println!(
                "  inclusion  : OK (seq={seq_num}, leaf_index={})",
                proof_resp.leaf_index
            );
        } else {
            anyhow::bail!("Inclusion proof verification FAILED for seq={seq_num}");
        }
    }

    println!("Verification complete.");
    Ok(())
}
