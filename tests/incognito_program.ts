import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  TOKEN_PROGRAM_ID,
  createMint,
  createAccount,
  mintTo,
  getAccount,
} from "@solana/spl-token";
import { expect } from "chai";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";

function pda(programId: PublicKey, seeds: (Buffer | Uint8Array)[]) {
  return PublicKey.findProgramAddressSync(seeds, programId)[0];
}

describe("incognito_program", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace
    .IncognitoProgram as Program<anchor.Idl>;

  async function ensureAirdrop(
    pubkey: PublicKey,
    minLamports: number,
    topUpLamports: number,
  ) {
    const bal = await provider.connection.getBalance(pubkey, "confirmed");
    if (bal >= minLamports) return;
    let lastErr: unknown = undefined;
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const sig = await provider.connection.requestAirdrop(
          pubkey,
          topUpLamports,
        );
        const latest = await provider.connection.getLatestBlockhash();
        await provider.connection.confirmTransaction(
          { signature: sig, ...latest },
          "confirmed",
        );
        return;
      } catch (e) {
        lastErr = e;
        await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
      }
    }
    throw lastErr;
  }

  it("deposits then withdraws with Groth16 proof (and blocks double-spend)", async function () {
    const payerKeypair = (provider.wallet as any).payer as Keypair;

    // Devnet is persistent; ensure every run uses a fresh nullifier so we don't
    // collide with previously-spent notes.
    const circuitsDir = path.resolve(__dirname, "../../incognito-circuits");
    execSync("node scripts/generate_vectors.js --random", {
      cwd: circuitsDir,
      stdio: "pipe",
    });
    execSync("node scripts/generate_proof.js", {
      cwd: circuitsDir,
      stdio: "pipe",
    });

    const fixturePath = path.resolve(
      __dirname,
      "../../incognito-circuits/build/proof_fixture.json",
    );
    const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8")) as {
      proofBytes: number[];
      commitmentBe: number[];
      publicInputsBe: { root: number[]; nullifierHash: number[] };
    };

    expect(fixture.proofBytes).to.have.length(256);
    expect(fixture.commitmentBe).to.have.length(32);
    expect(fixture.publicInputsBe.root).to.have.length(32);
    expect(fixture.publicInputsBe.nullifierHash).to.have.length(32);

    const payer = provider.wallet;

    // Devnet: make sure the payer has SOL (localnet: no-op).
    await ensureAirdrop(
      payer.publicKey,
      0.5 * anchor.web3.LAMPORTS_PER_SOL,
      2 * anchor.web3.LAMPORTS_PER_SOL,
    );

    const state = pda(program.programId, [Buffer.from("state")]);
    const vault = pda(program.programId, [Buffer.from("vault")]);

    const existingStateInfo = await provider.connection.getAccountInfo(
      state,
      "confirmed",
    );

    let mint: PublicKey;
    let denomination = 1;
    let vaultBalanceBefore = 0;

    if (!existingStateInfo) {
      mint = await createMint(
        provider.connection,
        payerKeypair,
        payer.publicKey,
        null,
        0,
      );

      await program.methods
        .initialize(
          new anchor.BN(1),
          Array(32).fill(0),
          payer.publicKey,
        )
        .accounts({
          payer: payer.publicKey,
          state,
          vault,
          mint,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
          rent: anchor.web3.SYSVAR_RENT_PUBKEY,
        })
        .rpc();
    } else {
      const stateAccount = await program.account.incognitoState.fetch(state);
      mint = stateAccount.mint as PublicKey;
      denomination = Number(stateAccount.denomination);
    }

    try {
      const vaultAccount = await getAccount(provider.connection, vault);
      vaultBalanceBefore = Number(vaultAccount.amount);
    } catch {
      vaultBalanceBefore = 0;
    }

    const destinationOwner = Keypair.generate();
    const depositorToken = await createAccount(
      provider.connection,
      payerKeypair,
      mint,
      payer.publicKey,
      Keypair.generate(),
    );
    const destinationToken = await createAccount(
      provider.connection,
      payerKeypair,
      mint,
      destinationOwner.publicKey,
      Keypair.generate(),
    );

    await program.methods
      .setRoot(fixture.publicInputsBe.root)
      .accounts({
        rootUpdater: payer.publicKey,
        state,
      })
      .rpc();

    await mintTo(
      provider.connection,
      payerKeypair,
      mint,
      depositorToken,
      payerKeypair,
      denomination,
    );

    await program.methods
      .deposit(fixture.commitmentBe)
      .accounts({
        depositor: payer.publicKey,
        depositorToken,
        state,
        vault,
        mint,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .rpc();

    const nullifier = pda(program.programId, [
      Buffer.from("nullifier"),
      Buffer.from(fixture.publicInputsBe.nullifierHash),
    ]);

    const tryWithdraw = async (proofBytes: number[]) =>
      program.methods
        .actionWithdraw(proofBytes, fixture.publicInputsBe.nullifierHash)
        .accounts({
          relayer: payer.publicKey,
          state,
          vault,
          nullifier,
          destination: destinationToken,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();

    try {
      await tryWithdraw(fixture.proofBytes);
    } catch (e: any) {
      if (e?.logs) console.error("withdraw logs:", e.logs);
      throw e;
    }

    const destinationAccount = await getAccount(
      provider.connection,
      destinationToken,
    );
    expect(Number(destinationAccount.amount)).to.equal(1);

    const vaultAccount = await getAccount(provider.connection, vault);
    expect(Number(vaultAccount.amount)).to.equal(vaultBalanceBefore);

    // Attempt to spend again with same nullifier should fail (PDA already initialized).
    let threw = false;
    try {
      await program.methods
        .actionWithdraw(fixture.proofBytes, fixture.publicInputsBe.nullifierHash)
        .accounts({
          relayer: payer.publicKey,
          state,
          vault,
          nullifier,
          destination: destinationToken,
          tokenProgram: TOKEN_PROGRAM_ID,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .rpc();
    } catch {
      threw = true;
    }
    expect(threw).to.equal(true);
  });
});
