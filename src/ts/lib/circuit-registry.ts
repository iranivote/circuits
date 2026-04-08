import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import type {
  CompiledCircuit,
  SignatureConfig,
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
// Modular circuit names (fixed — no per-algorithm variants)
// ---------------------------------------------------------------------------

function signupCircuitName(sig: SignatureConfig): string {
  return sig.type === "rsa" ? "signup_verify_rsa" : "signup_verify_ecdsa";
}

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
// Public API
// ---------------------------------------------------------------------------

export function getSignupCircuit(
  dscSig: SignatureConfig,
): { circuit: CompiledCircuit; name: string } {
  const name = signupCircuitName(dscSig);
  return { circuit: loadCircuit(name), name };
}

export function getSignupCircuitForDscKind(
  dscKind: "rsa" | "ecdsa",
): { circuit: CompiledCircuit; name: string } {
  const name = dscKind === "rsa" ? "signup_verify_rsa" : "signup_verify_ecdsa";
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
