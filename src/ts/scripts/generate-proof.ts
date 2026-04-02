#!/usr/bin/env tsx
/**
 * Generate a Noir passport proof for testing.
 *
 * Usage:
 *   npx tsx scripts/generate-proof.ts \
 *     --mrz1 "P<IRNREZAEE<<ALI<<<<<<<<<<<<<<<<<<<<<<<<<<<< " \
 *     --mrz2 "A1234567<8IRN9503152M3001015<<<<<<<<<<<<<<04" \
 *     [--stage dsc|id-data|integrity|age|all] \
 *     [--sig rsa-pkcs-2048] \
 *     [--hash sha256] \
 *     [--mock]
 *
 * With --mock: uses a mock certificate registry and random crypto values
 * to test the full pipeline structurally (proof generation works but
 * crypto verification stubs return true).
 */

import { fileURLToPath } from "url";
import * as path from "path";
import * as fs from "fs";
import {
  generateProof,
  verifyProof,
  executeCircuit,
  getDscCircuit,
  getIdDataCircuit,
  getIntegrityCircuit,
  getDisclosureCircuit,
  buildDg1FromMrz,
  buildDscInputs,
  buildIdDataInputs,
  buildIntegrityInputs,
  buildAgeDisclosureInputs,
  buildMockRegistryProof,
  randomSalt,
} from "../lib/index.js";
import type {
  PassportData,
  RsaSigConfig,
  HashAlgorithm,
  ProofResult,
} from "../lib/types.js";
import { randomBytes } from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

function getArg(name: string, required = false): string {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) {
    if (required) {
      console.error(`Missing required argument: --${name}`);
      process.exit(1);
    }
    return "";
  }
  return process.argv[idx + 1];
}

function hasFlag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

const mrzLine1 = getArg("mrz1", !hasFlag("mock"));
const mrzLine2 = getArg("mrz2", !hasFlag("mock"));
const stage = getArg("stage") || "all";
const sigArg = getArg("sig") || "rsa-pkcs-2048";
const hashArg = (getArg("hash") || "sha256") as HashAlgorithm;
const isMock = hasFlag("mock");

// ---------------------------------------------------------------------------
// Build mock passport data
// ---------------------------------------------------------------------------

function buildMockPassportData(
  mrz1: string,
  mrz2: string,
  sig: RsaSigConfig,
): PassportData {
  const dg1 = buildDg1FromMrz(mrz1, mrz2);
  const modBytes = Math.ceil(sig.bitSize / 8);

  return {
    mrzLine1: mrz1,
    mrzLine2: mrz2,
    dg1,
    sod: new Uint8Array(0),
    tbsCertificate: randomBytes(500),
    dscPubkey: randomBytes(modBytes),
    dscPubkeyRedcParam: randomBytes(modBytes + 1),
    sodSignature: randomBytes(modBytes),
    signedAttributes: randomBytes(200),
    eContent: randomBytes(300),
    cscPubkey: randomBytes(modBytes),
    cscPubkeyRedcParam: randomBytes(modBytes + 1),
    cscSignature: randomBytes(modBytes),
    sigConfig: sig,
    dgHashAlgorithm: hashArg,
    saHashAlgorithm: hashArg,
    rsaExponent: 65537,
  };
}

function parseSigArg(s: string): RsaSigConfig {
  const parts = s.split("-");
  if (parts.length !== 3 || parts[0] !== "rsa") {
    console.error(`Invalid --sig format. Expected: rsa-pkcs-2048 or rsa-pss-4096`);
    process.exit(1);
  }
  return {
    type: "rsa",
    padding: parts[1] as "pkcs" | "pss",
    bitSize: parseInt(parts[2], 10) as 1024 | 2048 | 3072 | 4096,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const sig = parseSigArg(sigArg);
  const effectiveMrz1 = mrzLine1 || "P<IRNREZAEE<<ALI<<<<<<<<<<<<<<<<<<<<<<<<<<<< ";
  const effectiveMrz2 = mrzLine2 || "A1234567<8IRN9503152M3001015<<<<<<<<<<<<<<04";

  console.error("Noir Passport Proof Generator");
  console.error("============================");
  console.error(`  Mode:       ${isMock ? "MOCK" : "REAL"}`);
  console.error(`  Stage:      ${stage}`);
  console.error(`  Signature:  ${sig.type}-${sig.padding}-${sig.bitSize}`);
  console.error(`  Hash:       ${hashArg}`);
  console.error(`  MRZ Line 1: ${effectiveMrz1}`);
  console.error(`  MRZ Line 2: ${effectiveMrz2}`);
  console.error("");

  const passport = buildMockPassportData(effectiveMrz1, effectiveMrz2, sig);
  const registryProof = buildMockRegistryProof();
  const tbsLen = passport.tbsCertificate.length;

  const results: Record<string, ProofResult> = {};
  const commitments: Record<string, string> = {};

  // -- Stage 1: DSC sig-check --
  if (stage === "all" || stage === "dsc") {
    console.error("Stage 1: DSC sig-check ...");
    const { circuit, name } = getDscCircuit(sig, hashArg, tbsLen);
    console.error(`  Circuit: ${name}`);

    const dscSalt = randomSalt();
    const inputs = buildDscInputs({ passport, registryProof, salt: dscSalt });
    // Strip internal metadata before passing to circuit
    const { _salt, ...circuitInputs } = inputs as any;

    const t0 = Date.now();
    const result = await generateProof(circuit, circuitInputs);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.error(`  Proof generated in ${elapsed}s`);
    console.error(`  Public inputs: ${result.publicInputs}`);

    const valid = await verifyProof(circuit, result.proof, result.publicInputs);
    console.error(`  Verified: ${valid}`);

    results.dsc = result;
    commitments.dsc = result.publicInputs[result.publicInputs.length - 1];
    console.error("");
  }

  // -- Stage 2: ID data sig-check --
  if (stage === "all" || stage === "id-data") {
    const dscCommitment = commitments.dsc ?? "0";
    console.error("Stage 2: ID data sig-check ...");
    const { circuit, name } = getIdDataCircuit(sig, hashArg, tbsLen);
    console.error(`  Circuit: ${name}`);

    const inputs = buildIdDataInputs({
      passport,
      dscCommitment,
    });
    const { _saltOut, ...circuitInputs } = inputs as any;

    const t0 = Date.now();
    const result = await generateProof(circuit, circuitInputs);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.error(`  Proof generated in ${elapsed}s`);
    console.error(`  Public inputs: ${result.publicInputs}`);

    const valid = await verifyProof(circuit, result.proof, result.publicInputs);
    console.error(`  Verified: ${valid}`);

    results.idData = result;
    commitments.idData = result.publicInputs[result.publicInputs.length - 1];
    console.error("");
  }

  // -- Stage 3: Data integrity --
  if (stage === "all" || stage === "integrity") {
    const idDataCommitment = commitments.idData ?? "0";
    console.error("Stage 3: Data integrity ...");
    const { circuit, name } = getIntegrityCircuit(hashArg, hashArg);
    console.error(`  Circuit: ${name}`);

    const inputs = buildIntegrityInputs({
      passport,
      idDataCommitment,
    });
    const { _dg1Salt, _expiryDateSalt, _dg2HashSalt, _privateNullifierSalt, _privateNullifier, ...circuitInputs } = inputs as any;

    const t0 = Date.now();
    const result = await generateProof(circuit, circuitInputs);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.error(`  Proof generated in ${elapsed}s`);

    const valid = await verifyProof(circuit, result.proof, result.publicInputs);
    console.error(`  Verified: ${valid}`);

    results.integrity = result;
    commitments.integrity = result.publicInputs[result.publicInputs.length - 1];
    console.error("");
  }

  // -- Stage 4: Age disclosure --
  if (stage === "all" || stage === "age") {
    const integrityCommitment = commitments.integrity ?? "0";
    console.error("Stage 4: Age disclosure ...");
    const { circuit, name } = getDisclosureCircuit("age");
    console.error(`  Circuit: ${name}`);

    const inputs = buildAgeDisclosureInputs({
      passport,
      integrityCommitment,
      currentDate: BigInt(Math.floor(Date.now() / 1000)),
      minAge: 18,
      maxAge: 120,
      serviceScope: "1",
      serviceSubscope: "0",
      salts: {
        dg1Salt: (inputs as any)?._dg1Salt ?? randomSalt(),
        expiryDateSalt: (inputs as any)?._expiryDateSalt ?? randomSalt(),
        dg2HashSalt: (inputs as any)?._dg2HashSalt ?? randomSalt(),
        privateNullifierSalt: (inputs as any)?._privateNullifierSalt ?? randomSalt(),
        privateNullifier: Array.from(randomBytes(32)),
      },
    });

    const t0 = Date.now();
    const result = await generateProof(circuit, inputs);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.error(`  Proof generated in ${elapsed}s`);

    const valid = await verifyProof(circuit, result.proof, result.publicInputs);
    console.error(`  Verified: ${valid}`);

    results.age = result;
    console.error("");
  }

  // -- Output --
  const output = {
    circuitNames: {
      dsc: results.dsc ? `sig_check_dsc_*` : undefined,
      idData: results.idData ? `sig_check_id_data_*` : undefined,
      integrity: results.integrity ? `data_check_integrity_*` : undefined,
      age: results.age ? `compare_age` : undefined,
    },
    proofs: Object.fromEntries(
      Object.entries(results).map(([k, v]) => [
        k,
        {
          proof: Buffer.from(v.proof).toString("hex"),
          publicInputs: v.publicInputs,
        },
      ]),
    ),
    commitments,
  };

  console.log(JSON.stringify(output, null, 2));
  console.error("Done.");
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
