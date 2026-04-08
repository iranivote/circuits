#!/usr/bin/env tsx
/**
 * Generate Noir proofs for local testing.
 *
 * Usage:
 *   npx tsx scripts/generate-proof.ts \
 *     --mrz1 "P<IRNREZAEE<<ALI<<<<<<<<<<<<<<<<<<<<<<<<<<<< " \
 *     --mrz2 "A1234567<8IRN9503152M3001015<<<<<<<<<<<<<<04" \
 *     [--stage signup|age|all] \
 *     [--sig rsa-pkcs-2048] \
 *     [--hash sha256] \
 *     [--mock]
 */

import {
  generateProof,
  verifyProof,
  getSignupCircuit,
  getDisclosureCircuit,
  buildDg1FromMrz,
  buildSignupVerifyInputsFromPassport,
  buildAgeDisclosureInputs,
  buildMockRegistryProof,
  deterministicSalt,
  deterministicNullifier,
} from "../lib/index.js";
import type {
  PassportData,
  RsaSigConfig,
  HashAlgorithm,
  ProofResult,
} from "../lib/types.js";
import { randomBytes } from "crypto";

function getArg(name: string, required = false): string {
  const idx = process.argv.indexOf(`--${name}`);
  if (idx === -1 || idx + 1 >= process.argv.length) {
    if (required) {
      console.error(`Missing required argument: --${name}`);
      process.exit(1);
    }
    return "";
  }
  return process.argv[idx + 1]!;
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

function buildMockPassportData(mrz1: string, mrz2: string, sig: RsaSigConfig): PassportData {
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

  const results: Record<string, ProofResult> = {};
  const commitments: Record<string, string> = {};

  if (stage === "all" || stage === "signup") {
    console.error("Stage: attested signup (signup_verify_*) ...");
    const { circuit, name } = getSignupCircuit(sig);
    console.error(`  Circuit: ${name}`);

    const inputs = buildSignupVerifyInputsFromPassport(passport, registryProof);

    const t0 = Date.now();
    let result: ProofResult;
    try {
      result = await generateProof(circuit, inputs);
    } catch (err) {
      console.error(`  Expected with random mock data: ${(err as Error).message.slice(0, 120)}`);
      result = { proof: new Uint8Array(0), publicInputs: [] };
    }
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.error(`  Proof generated in ${elapsed}s`);
    if (result.publicInputs.length > 0) {
      console.error(`  Public inputs: ${result.publicInputs}`);
      const valid = await verifyProof(circuit, result.proof, result.publicInputs);
      console.error(`  Verified: ${valid}`);
      results.signup = result;
      commitments.signup = result.publicInputs[result.publicInputs.length - 1]!;
    }
    console.error("");
  }

  if (stage === "all" || stage === "age") {
    const passportCommitment = commitments.signup ?? "0";
    console.error("Stage: Age disclosure ...");
    const { circuit, name } = getDisclosureCircuit("age");
    console.error(`  Circuit: ${name}`);

    const dg1 = passport.dg1;
    const salts = {
      dg1Salt: deterministicSalt(dg1, "integrity-dg1"),
      expiryDateSalt: deterministicSalt(dg1, "integrity-expiry"),
      dg2HashSalt: deterministicSalt(dg1, "integrity-dg2-hash"),
      privateNullifierSalt: deterministicSalt(dg1, "integrity-nullifier-salt"),
      privateNullifier: Array.from(deterministicNullifier(dg1)),
    };

    const ageInputs = buildAgeDisclosureInputs({
      passport,
      integrityCommitment: passportCommitment,
      currentDate: BigInt(Math.floor(Date.now() / 1000)),
      minAge: 18,
      maxAge: 120,
      serviceScope: "1",
      serviceSubscope: "0",
      salts,
    });

    const t0 = Date.now();
    const result = await generateProof(circuit, ageInputs);
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    console.error(`  Proof generated in ${elapsed}s`);

    const valid = await verifyProof(circuit, result.proof, result.publicInputs);
    console.error(`  Verified: ${valid}`);

    results.age = result;
    console.error("");
  }

  const output = {
    circuitNames: {
      signup: results.signup ? `signup_verify_rsa` : undefined,
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
