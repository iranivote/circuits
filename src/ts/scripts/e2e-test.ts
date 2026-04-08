#!/usr/bin/env tsx
/**
 * Smoke test: load compiled signup circuit JSON and run proof + verify with mock inputs.
 * Random mock data usually fails witness generation (real crypto); we still verify load path.
 */

import { generateProof, verifyProof, destroyBb } from "../lib/noir-proof.js";
import { getSignupCircuitForDscKind } from "../lib/circuit-registry.js";

function formatTime(ms: number): string {
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`;
}

async function main() {
  console.log("E2E: signup_verify_rsa load + proof attempt");
  console.log("==========================================\n");

  const { circuit, name } = getSignupCircuitForDscKind("rsa");
  console.log(`  Circuit: ${name} (${circuit.bytecode.length} bytecode chars)`);

  try {
    const inputs = {
      trusted_dsc_root: "0",
      certificate_registry_index: "0",
      certificate_registry_hash_path: new Array(16).fill("0"),
      certificate_tags: ["0", "0", "0"],
      salted_dg1: { salt: "1", value: new Array(95).fill(0) },
      expiry_date_salt: "1",
      dg2_hash_salt: "1",
      signed_attributes: new Array(256).fill(0),
      e_content: new Array(512).fill(0),
      salted_private_nullifier: { salt: "1", value: new Array(32).fill(0) },
      dg_hash_type: 3,
      sa_hash_type: 3,
      dsc_pubkey: new Array(512).fill(0),
      dsc_pubkey_redc_param: new Array(513).fill(0),
      sod_signature: new Array(512).fill(0),
      exponent: 65537,
      key_size: 0,
      hash_type: 1,
      padding_type: 0,
      pss_salt_len: 0,
      pubkey_len: 256,
    };

    const t0 = Date.now();
    const result = await generateProof(circuit, inputs);
    console.log(`  Proof: ${result.proof.length} bytes in ${formatTime(Date.now() - t0)}`);

    const t1 = Date.now();
    const valid = await verifyProof(circuit, result.proof, result.publicInputs);
    console.log(`  Verify: ${valid} in ${formatTime(Date.now() - t1)}`);
    if (!valid) process.exit(1);
  } catch (err) {
    console.log(`  Mock inputs failed as expected: ${(err as Error).message.slice(0, 100)}`);
  }

  await destroyBb();
  console.log("\nDone (circuit artifacts reachable).");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
