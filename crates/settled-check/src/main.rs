use anyhow::Context;
use clap::{Parser, Subcommand};
use settled_sdk::verifier::{verify_inclusion, verify_tree_head};
use settled_sdk::SettledClient;

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
    let mut client = SettledClient::connect(server.to_owned())
        .await
        .context("Failed to connect to Settled server")?;

    let sth = client
        .get_sth(0)
        .await
        .context("Failed to fetch latest STH")?;

    println!("Latest STH:");
    println!("  tree_size  : {}", sth.tree_size);
    println!("  root_hash  : {}", hex::encode(&sth.root_hash));
    println!("  timestamp  : {} ns", sth.timestamp_ns);
    println!("  key_version: {}", sth.key_version);

    let root: [u8; 32] = sth
        .root_hash
        .as_slice()
        .try_into()
        .context("root_hash must be 32 bytes")?;

    if !verify_tree_head(sth.tree_size, root, sth.timestamp_ns, &sth.signature, &sth.public_key) {
        anyhow::bail!("STH signature verification FAILED");
    }
    println!("  signature  : OK");

    if let Some(seq_num) = seq {
        let proof_res = client
            .inclusion_proof(seq_num, sth.tree_size)
            .await
            .context("Failed to fetch inclusion proof")?;

        let path: Vec<[u8; 32]> = proof_res
            .proof
            .iter()
            .map(|h| {
                h.as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("proof node must be 32 bytes"))
            })
            .collect::<anyhow::Result<_>>()?;

        let entry = client
            .get(seq_num)
            .await
            .context("Failed to fetch entry")?;

        let leaf: [u8; 32] = entry
            .leaf_hash
            .as_slice()
            .try_into()
            .context("leaf_hash must be 32 bytes")?;

        if verify_inclusion(leaf, proof_res.leaf_index, sth.tree_size, &path, root) {
            println!(
                "  inclusion  : OK (seq={seq_num}, leaf_index={})",
                proof_res.leaf_index
            );
        } else {
            anyhow::bail!("Inclusion proof verification FAILED for seq={seq_num}");
        }
    }

    println!("Verification complete.");
    Ok(())
}
