import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import type {
  CompiledCircuit,
  SignatureConfig,
  HashAlgorithm,
  HashAlgorithmExtended,
  RsaSigConfig,
  EcdsaSigConfig,
} from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CIRCUITS_ROOT = path.resolve(__dirname, "../../..");
const TARGET_DIR = path.join(CIRCUITS_ROOT, "target");

const circuitCache = new Map<string, CompiledCircuit>();

function loadCircuit(name: string): CompiledCircuit {
  const cached = circuitCache.get(name);
  if (cached) return cached;

  const filePath = path.join(TARGET_DIR, `${name}.json`);
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `Compiled circuit not found: ${filePath}\n` +
        `Run: cd circuits/src/ts && npm run compile -- --filter=${name}`,
    );
  }
  const json = JSON.parse(fs.readFileSync(filePath, "utf-8")) as CompiledCircuit;
  circuitCache.set(name, json);
  return json;
}

// ---------------------------------------------------------------------------
// Name builders -- must match circuit-builder.ts naming conventions
// ---------------------------------------------------------------------------

function dscCircuitName(
  sig: SignatureConfig,
  hash: HashAlgorithm,
  tbsMaxLen: number,
): string {
  if (sig.type === "rsa") {
    const rsa = sig as RsaSigConfig;
    return `sig_check_dsc_tbs_${tbsMaxLen}_rsa_${rsa.padding}_${rsa.bitSize}_${hash}`;
  }
  const ec = sig as EcdsaSigConfig;
  return `sig_check_dsc_tbs_${tbsMaxLen}_ecdsa_${ec.family}_${ec.curveName}_${hash}`;
}

function idDataCircuitName(
  sig: SignatureConfig,
  hash: HashAlgorithm,
  tbsMaxLen: number,
): string {
  if (sig.type === "rsa") {
    const rsa = sig as RsaSigConfig;
    return `sig_check_id_data_tbs_${tbsMaxLen}_rsa_${rsa.padding}_${rsa.bitSize}_${hash}`;
  }
  const ec = sig as EcdsaSigConfig;
  return `sig_check_id_data_tbs_${tbsMaxLen}_ecdsa_${ec.family}_${ec.curveName}_${hash}`;
}

function integrityCircuitName(
  saHash: HashAlgorithmExtended,
  dgHash: HashAlgorithmExtended,
): string {
  return `data_check_integrity_sa_${saHash}_dg_${dgHash}`;
}

// Static disclosure circuits have fixed names
const DISCLOSURE_NAMES: Record<string, string> = {
  age: "compare_age",
  nationality_inclusion: "inclusion_check_nationality",
  nationality_exclusion: "exclusion_check_nationality",
  place_of_birth_inclusion: "inclusion_check_place_of_birth",
  place_of_birth_exclusion: "exclusion_check_place_of_birth",
  disclose: "disclose_bytes",
  bind: "bind",
};

// ---------------------------------------------------------------------------
// Determine TBS max length bucket
// ---------------------------------------------------------------------------

const TBS_BUCKETS = [700, 1000, 1200];

export function selectTbsBucket(tbsLength: number): number {
  for (const bucket of TBS_BUCKETS) {
    if (tbsLength <= bucket) return bucket;
  }
  throw new Error(
    `TBS certificate too large (${tbsLength} bytes). Max supported: ${TBS_BUCKETS[TBS_BUCKETS.length - 1]}`,
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function getDscCircuit(
  sig: SignatureConfig,
  hash: HashAlgorithm,
  tbsLength: number,
): { circuit: CompiledCircuit; name: string } {
  const bucket = selectTbsBucket(tbsLength);
  const name = dscCircuitName(sig, hash, bucket);
  return { circuit: loadCircuit(name), name };
}

export function getIdDataCircuit(
  sig: SignatureConfig,
  hash: HashAlgorithm,
  tbsLength: number,
): { circuit: CompiledCircuit; name: string } {
  const bucket = selectTbsBucket(tbsLength);
  const name = idDataCircuitName(sig, hash, bucket);
  return { circuit: loadCircuit(name), name };
}

export function getIntegrityCircuit(
  saHash: HashAlgorithmExtended,
  dgHash: HashAlgorithmExtended,
): { circuit: CompiledCircuit; name: string } {
  const name = integrityCircuitName(saHash, dgHash);
  return { circuit: loadCircuit(name), name };
}

export function getDisclosureCircuit(
  disclosureType: string,
): { circuit: CompiledCircuit; name: string } {
  const name = DISCLOSURE_NAMES[disclosureType];
  if (!name) {
    throw new Error(
      `Unknown disclosure type: ${disclosureType}. ` +
        `Available: ${Object.keys(DISCLOSURE_NAMES).join(", ")}`,
    );
  }
  return { circuit: loadCircuit(name), name };
}

/** List all compiled circuit JSON files in target/ */
export function listCompiledCircuits(): string[] {
  if (!fs.existsSync(TARGET_DIR)) return [];
  return fs
    .readdirSync(TARGET_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.replace(/\.json$/, ""));
}

/** Preload circuits into the cache for faster subsequent access */
export function preloadCircuits(names: string[]): void {
  for (const name of names) {
    loadCircuit(name);
  }
}
