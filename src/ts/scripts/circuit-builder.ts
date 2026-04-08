import * as fs from "fs";
import * as path from "path";
import { exec, execSync } from "child_process";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_CONCURRENCY = 8;
const CIRCUITS_ROOT = path.resolve(__dirname, "../../..");

function findNargo(): string {
  try {
    return execSync("which nargo", { encoding: "utf-8" }).trim();
  } catch {
    const candidates = [
      path.join(process.env.HOME || "", ".nargo/bin/nargo"),
      "/usr/local/bin/nargo",
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) return c;
    }
    throw new Error(
      "nargo not found. Install it via `curl -L noiup.org | bash && noiup` or add it to PATH.",
    );
  }
}
const NARGO = findNargo();

function ensureDir(filePath: string) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tracking
// ─────────────────────────────────────────────────────────────────────────────

const generatedCircuits: { name: string; path: string }[] = [];

// ─────────────────────────────────────────────────────────────────────────────
// Nargo.toml template
// ─────────────────────────────────────────────────────────────────────────────

function nargoToml(
  name: string,
  deps: { name: string; path: string }[],
): string {
  return `[package]
name = "${name}"
type = "bin"
authors = ["IraniVote"]
compiler_version = ">=1.0.0"

[dependencies]
${deps.map((d) => `${d.name} = { path = "${d.path}" }`).join("\n")}
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Library member paths (for workspace Nargo.toml)
// ─────────────────────────────────────────────────────────────────────────────

const LIB_MEMBERS = [
  "src/noir/lib/utils",
  "src/noir/lib/commitment/common",
  "src/noir/lib/commitment/scoped-nullifier",
  "src/noir/lib/commitment/dsc-to-id",
  "src/noir/lib/commitment/integrity-to-disclosure",
  "src/noir/lib/sig-check/common",
  "src/noir/lib/sig-check/rsa",
  "src/noir/lib/sig-check/ecdsa",
  "src/noir/lib/sig-verify/rsa",
  "src/noir/lib/sig-verify/ecdsa",
  "src/noir/lib/hash-multiplex",
  "src/noir/lib/data-check/integrity",
  "src/noir/lib/data-check/expiry",
  "src/noir/lib/data-check/tbs-pubkey",
  "src/noir/lib/data-check/dg11",
  "src/noir/lib/compare/age",
  "src/noir/lib/compare/date",
  "src/noir/lib/disclose",
  "src/noir/lib/inclusion-check/country",
  "src/noir/lib/inclusion-check/place-of-birth",
  "src/noir/lib/exclusion-check/country",
  "src/noir/lib/exclusion-check/place-of-birth",
  "src/noir/lib/exclusion-check/sanctions",
  "src/noir/lib/bind",
];

// ─────────────────────────────────────────────────────────────────────────────
// Static circuit definitions (7 disclosure/nullifier circuits)
// ─────────────────────────────────────────────────────────────────────────────

const STATIC_CIRCUITS: { name: string; path: string }[] = [
  { name: "compare_age", path: "src/noir/bin/compare/age/standard" },
  { name: "inclusion_check_nationality", path: "src/noir/bin/inclusion-check/nationality/standard" },
  { name: "exclusion_check_nationality", path: "src/noir/bin/exclusion-check/nationality/standard" },
  { name: "inclusion_check_place_of_birth", path: "src/noir/bin/inclusion-check/place-of-birth/standard" },
  { name: "exclusion_check_place_of_birth", path: "src/noir/bin/exclusion-check/place-of-birth/standard" },
  { name: "disclose_bytes", path: "src/noir/bin/disclose/bytes/standard" },
  { name: "bind", path: "src/noir/bin/bind/standard" },
];

// ─────────────────────────────────────────────────────────────────────────────
// Modular signup circuits (RSA / ECDSA DSC signing)
// ─────────────────────────────────────────────────────────────────────────────

const MODULAR_CIRCUITS: { name: string; path: string }[] = [
  { name: "signup_verify_rsa", path: "src/noir/bin/signup-verify/rsa" },
  { name: "signup_verify_ecdsa", path: "src/noir/bin/signup-verify/ecdsa" },
];

// ─────────────────────────────────────────────────────────────────────────────
// Static circuit Noir source templates
// ─────────────────────────────────────────────────────────────────────────────

function relLibPath(circuitPath: string, libSub: string): string {
  const depth = circuitPath.split("/").length;
  const upToNoirDir = depth - 2;
  return "../".repeat(upToNoirDir) + `lib/${libSub}`;
}

function writeStaticCircuit(name: string, circuitPath: string, noirSrc: string, libDeps: { name: string; lib: string }[]) {
  const deps = libDeps.map((d) => ({ name: d.name, path: relLibPath(circuitPath, d.lib) }));
  const absPath = path.join(CIRCUITS_ROOT, circuitPath);
  const mainPath = path.join(absPath, "src/main.nr");
  const tomlPath = path.join(absPath, "Nargo.toml");
  ensureDir(mainPath);
  fs.writeFileSync(mainPath, noirSrc);
  fs.writeFileSync(tomlPath, nargoToml(name, deps));
}

function generateStaticCircuits() {
  console.log("Generating static circuits...");

  writeStaticCircuit("compare_age", "src/noir/bin/compare/age/standard",
`use commitment::nullify;
use compare_age::{calculate_param_commitment, compare_age};
use data_check_expiry::check_expiry;
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    min_age_required: u8,
    max_age_required: u8,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    compare_age(salted_dg1.value, min_age_required, max_age_required, current_date);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(min_age_required, max_age_required);
    (param_commitment, nullifier_type, nullifier)
}
`, [
    { name: "compare_age", lib: "compare/age" },
    { name: "commitment", lib: "commitment/scoped-nullifier" },
    { name: "utils", lib: "utils" },
    { name: "data_check_expiry", lib: "data-check/expiry" },
  ]);

  writeStaticCircuit("inclusion_check_nationality", "src/noir/bin/inclusion-check/nationality/standard",
`use commitment::nullify;
use data_check_expiry::check_expiry;
use inclusion_check_country::{calculate_param_commitment, check_nationality_inclusion};
use utils::constants::PROOF_TYPE_NATIONALITY_INCLUSION;
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    country_list: [u32; 200],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    check_nationality_inclusion(salted_dg1.value, country_list);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(PROOF_TYPE_NATIONALITY_INCLUSION, country_list);
    (param_commitment, nullifier_type, nullifier)
}
`, [
    { name: "inclusion_check_country", lib: "inclusion-check/country" },
    { name: "commitment", lib: "commitment/scoped-nullifier" },
    { name: "utils", lib: "utils" },
    { name: "data_check_expiry", lib: "data-check/expiry" },
  ]);

  writeStaticCircuit("exclusion_check_nationality", "src/noir/bin/exclusion-check/nationality/standard",
`use commitment::nullify;
use data_check_expiry::check_expiry;
use exclusion_check_country::{calculate_param_commitment, check_nationality_exclusion};
use utils::constants::PROOF_TYPE_NATIONALITY_EXCLUSION;
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    country_list: [u32; 200],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    check_nationality_exclusion(salted_dg1.value, country_list);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(PROOF_TYPE_NATIONALITY_EXCLUSION, country_list);
    (param_commitment, nullifier_type, nullifier)
}
`, [
    { name: "exclusion_check_country", lib: "exclusion-check/country" },
    { name: "commitment", lib: "commitment/scoped-nullifier" },
    { name: "utils", lib: "utils" },
    { name: "data_check_expiry", lib: "data-check/expiry" },
  ]);

  writeStaticCircuit("inclusion_check_place_of_birth", "src/noir/bin/inclusion-check/place-of-birth/standard",
`use commitment::nullify;
use data_check_expiry::check_expiry;
use data_check_dg11::{extract_place_of_birth, PLACE_OF_BIRTH_MAX_LENGTH};
use inclusion_check_place_of_birth::{calculate_param_commitment, check_place_of_birth_inclusion, POB_LIST_SIZE};
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    dg11: [u8; 512],
    dg11_len: u32,
    pob_list: [[u8; PLACE_OF_BIRTH_MAX_LENGTH]; POB_LIST_SIZE],
    pob_list_lengths: [u32; POB_LIST_SIZE],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    let (pob, pob_len) = extract_place_of_birth(dg11, dg11_len);
    check_place_of_birth_inclusion(pob, pob_len, pob_list, pob_list_lengths);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(pob_list, pob_list_lengths);
    (param_commitment, nullifier_type, nullifier)
}
`, [
    { name: "inclusion_check_place_of_birth", lib: "inclusion-check/place-of-birth" },
    { name: "data_check_dg11", lib: "data-check/dg11" },
    { name: "commitment", lib: "commitment/scoped-nullifier" },
    { name: "utils", lib: "utils" },
    { name: "data_check_expiry", lib: "data-check/expiry" },
  ]);

  writeStaticCircuit("exclusion_check_place_of_birth", "src/noir/bin/exclusion-check/place-of-birth/standard",
`use commitment::nullify;
use data_check_expiry::check_expiry;
use data_check_dg11::{extract_place_of_birth, PLACE_OF_BIRTH_MAX_LENGTH};
use exclusion_check_place_of_birth::{calculate_param_commitment, check_place_of_birth_exclusion, POB_LIST_SIZE};
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    dg11: [u8; 512],
    dg11_len: u32,
    pob_list: [[u8; PLACE_OF_BIRTH_MAX_LENGTH]; POB_LIST_SIZE],
    pob_list_lengths: [u32; POB_LIST_SIZE],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    let (pob, pob_len) = extract_place_of_birth(dg11, dg11_len);
    check_place_of_birth_exclusion(pob, pob_len, pob_list, pob_list_lengths);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(pob_list, pob_list_lengths);
    (param_commitment, nullifier_type, nullifier)
}
`, [
    { name: "exclusion_check_place_of_birth", lib: "exclusion-check/place-of-birth" },
    { name: "data_check_dg11", lib: "data-check/dg11" },
    { name: "commitment", lib: "commitment/scoped-nullifier" },
    { name: "utils", lib: "utils" },
    { name: "data_check_expiry", lib: "data-check/expiry" },
  ]);

  writeStaticCircuit("disclose_bytes", "src/noir/bin/disclose/bytes/standard",
`use commitment::nullify;
use data_check_expiry::check_expiry;
use disclose::{calculate_param_commitment, get_disclosed_bytes};
use utils::types::{DiscloseMask, SaltedValue};

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    disclose_mask: DiscloseMask,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry(salted_dg1.value, current_date);
    let disclosed_bytes = get_disclosed_bytes(salted_dg1.value, disclose_mask);
    let (scoped_nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(disclose_mask, disclosed_bytes);
    (param_commitment, nullifier_type, scoped_nullifier)
}
`, [
    { name: "disclose", lib: "disclose" },
    { name: "commitment", lib: "commitment/scoped-nullifier" },
    { name: "utils", lib: "utils" },
    { name: "data_check_expiry", lib: "data-check/expiry" },
  ]);

  writeStaticCircuit("bind", "src/noir/bin/bind/standard",
`use bind::calculate_param_commitment;
use commitment::nullify;
use data_check_expiry::check_expiry_from_date;
use utils::types::SaltedValue;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<32>,
    salted_expiry_date: SaltedValue<6>,
    salted_dg1: SaltedValue<95>,
    salted_dg2_hash: SaltedValue<64>,
    salted_dg2_hash_type: SaltedValue<1>,
    data: [u8; 509],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    check_expiry_from_date(salted_expiry_date.value, current_date);
    let (nullifier, nullifier_type) = nullify(
        comm_in, salted_dg1, salted_expiry_date, salted_dg2_hash,
        salted_dg2_hash_type, salted_private_nullifier,
        service_scope, service_subscope, nullifier_secret,
    );
    let param_commitment = calculate_param_commitment(data);
    (param_commitment, nullifier_type, nullifier)
}
`, [
    { name: "bind", lib: "bind" },
    { name: "commitment", lib: "commitment/scoped-nullifier" },
    { name: "utils", lib: "utils" },
    { name: "data_check_expiry", lib: "data-check/expiry" },
  ]);

  console.log(`  Generated ${STATIC_CIRCUITS.length} static circuits`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Workspace Nargo.toml writer
// ─────────────────────────────────────────────────────────────────────────────

function generateWorkspaceToml() {
  const allBinPaths = [
    ...STATIC_CIRCUITS.map((c) => c.path),
    ...MODULAR_CIRCUITS.map((c) => c.path),
  ];
  const allMembers = [...allBinPaths, ...LIB_MEMBERS];
  const toml = `[workspace]\nmembers = [\n${allMembers.map((m) => `  "${m}"`).join(",\n")},\n]\n`;
  fs.writeFileSync(path.join(CIRCUITS_ROOT, "Nargo.toml"), toml);
  console.log(`Updated workspace Nargo.toml with ${allMembers.length} members (${allBinPaths.length} bin + ${LIB_MEMBERS.length} lib)`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Compiler
// ─────────────────────────────────────────────────────────────────────────────

class PromisePool {
  private queue: (() => Promise<void>)[] = [];
  private active = 0;

  constructor(private concurrency: number) {}

  async add(fn: () => Promise<void>) {
    if (this.active >= this.concurrency) {
      await new Promise<void>((resolve) => {
        this.queue.push(async () => { await fn(); resolve(); });
      });
    } else {
      this.active++;
      try { await fn(); } finally {
        this.active--;
        if (this.queue.length > 0) { this.add(this.queue.shift()!); }
      }
    }
  }
}

async function compileCircuits(concurrency: number, force: boolean, filter?: string) {
  const allCircuits = [...STATIC_CIRCUITS, ...MODULAR_CIRCUITS];
  let toCompile = force
    ? allCircuits
    : allCircuits.filter(({ name }) => !fs.existsSync(path.join(CIRCUITS_ROOT, "target", `${name}.json`)));

  if (filter) {
    toCompile = toCompile.filter(({ name }) => name.includes(filter));
  }

  if (toCompile.length === 0) {
    console.log("No circuits to compile (all up to date)");
    return;
  }

  console.log(`Compiling ${toCompile.length} circuits (concurrency: ${concurrency})...`);
  const startTime = Date.now();
  const pool = new PromisePool(concurrency);
  const promises: Promise<void>[] = [];
  let compiled = 0;

  for (const { name } of toCompile) {
    const idx = ++compiled;
    promises.push(
      pool.add(async () => {
        console.log(`  [${idx}/${toCompile.length}] Compiling ${name}...`);
        await new Promise<void>((resolve, reject) => {
          exec(
            `"${NARGO}" compile --force --package ${name}`,
            { cwd: CIRCUITS_ROOT, maxBuffer: 100 * 1024 * 1024 },
            (error, _stdout, _stderr) => {
              if (error) {
                console.error(`  FAILED: ${name}: ${error.message}`);
                resolve();
              } else {
                console.log(`  OK: ${name} (${idx}/${toCompile.length})`);
                resolve();
              }
            },
          );
        });
      }),
    );
  }

  await Promise.all(promises);
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`Done. Compiled ${compiled} circuits in ${elapsed}s`);
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);

if (args.includes("generate")) {
  generateStaticCircuits();
  generateWorkspaceToml();

  const total = STATIC_CIRCUITS.length + MODULAR_CIRCUITS.length;
  console.log(`\nTotal: ${total} circuits (${STATIC_CIRCUITS.length} static + ${MODULAR_CIRCUITS.length} modular)`);
}

if (args.includes("compile")) {
  let concurrency = DEFAULT_CONCURRENCY;
  const cArg = args.find((a) => a.startsWith("--concurrency="));
  if (cArg) {
    const v = parseInt(cArg.split("=")[1], 10);
    if (!isNaN(v) && v > 0) concurrency = v;
  }
  const force = args.includes("--force");
  const filterArg = args.find((a) => a.startsWith("--filter="));
  const filter = filterArg ? filterArg.split("=")[1] : undefined;

  compileCircuits(concurrency, force, filter).catch(console.error);
}

if (!args.includes("generate") && !args.includes("compile")) {
  console.log(`Usage:
  ts-node scripts/circuit-builder.ts generate              Generate all circuit source files
  ts-node scripts/circuit-builder.ts compile               Compile all circuits with nargo
  ts-node scripts/circuit-builder.ts generate compile      Both

Options:
  --concurrency=N    Max parallel compilations (default: ${DEFAULT_CONCURRENCY})
  --force            Recompile even if target exists
  --filter=<substr>  Only compile circuits whose name contains <substr>
`);
}
