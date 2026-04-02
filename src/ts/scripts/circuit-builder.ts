import * as fs from "fs";
import * as path from "path";
import { exec, execSync } from "child_process";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const CERTIFICATE_REGISTRY_HEIGHT = 16;
const SIGNED_ATTRIBUTES_SIZE = 256;
const DEFAULT_CONCURRENCY = 8;

// Root of the circuits workspace (two levels up from src/ts)
const CIRCUITS_ROOT = path.resolve(__dirname, "../../..");

// Resolve nargo binary -- check PATH first, then common install locations
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

type HashAlgorithm = "sha1" | "sha256" | "sha384" | "sha512";
type HashAlgorithmExtended = "sha1" | "sha224" | "sha256" | "sha384" | "sha512";
type RsaType = "pss" | "pkcs";

function ensureDir(filePath: string) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function getHashByteSize(h: HashAlgorithm | HashAlgorithmExtended): number {
  const map: Record<string, number> = { sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64 };
  return map[h]!;
}

function getHashIdentifier(h: HashAlgorithmExtended): string {
  return `${h.toUpperCase()}_IDENTIFIER`;
}

function getHashDigestLength(h: HashAlgorithmExtended): string {
  return `${h.toUpperCase()}_DIGEST_LENGTH`;
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
// Static circuit definitions
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

  // ── compare_age ─────────────────────────────────────────────────────
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

  // ── inclusion_check_nationality ─────────────────────────────────────
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

  // ── exclusion_check_nationality ─────────────────────────────────────
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

  // ── inclusion_check_place_of_birth ──────────────────────────────────
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

  // ── exclusion_check_place_of_birth ──────────────────────────────────
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

  // ── disclose_bytes ──────────────────────────────────────────────────
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

  // ── bind ────────────────────────────────────────────────────────────
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
// Generated circuit templates: DSC sig-check
// ─────────────────────────────────────────────────────────────────────────────

function dscRsaTemplate(rsaType: RsaType, bitSize: number, tbsMaxLen: number, hash: HashAlgorithm): string {
  const modBytes = Math.ceil(bitSize / 8);
  return `// Auto-generated by circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_rsa::verify_rsa${bitSize}_${hash}_${rsaType};
use utils::types::Alpha3CountryCode;

fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; ${CERTIFICATE_REGISTRY_HEIGHT}],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    tbs_certificate: [u8; ${tbsMaxLen}],
    csc_pubkey: [u8; ${modBytes}],
    csc_pubkey_redc_param: [u8; ${modBytes + 1}],
    dsc_signature: [u8; ${modBytes}],
    exponent: u32,${rsaType === "pss" ? "\n    pss_salt_len: u32," : ""}
) -> pub Field {
    // Safety: length is verified by the hash + signature check
    let tbs_certificate_len = unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    assert(
        verify_rsa${bitSize}_${hash}_${rsaType}(
            csc_pubkey, dsc_signature, csc_pubkey_redc_param, exponent,
            tbs_certificate, tbs_certificate_len,${rsaType === "pss" ? " pss_salt_len," : ""}
        ),
        "RSA signature verification failed",
    );
    commit_to_dsc(
        certificate_registry_root, certificate_registry_index,
        certificate_registry_hash_path, certificate_tags,
        country, tbs_certificate, salt, csc_pubkey,
    )
}
`;
}

function dscEcdsaTemplate(curveFamily: string, curveName: string, bitSize: number, tbsMaxLen: number, hash: HashAlgorithm): string {
  const coordBytes = Math.ceil(bitSize / 8);
  return `// Auto-generated by circuit-builder.ts
use commitment::commit_to_dsc;
use sig_check_common::${hash}_and_check_data_to_sign;
use sig_check_ecdsa::verify_${curveFamily}_${curveName};
use utils::{split_array, types::Alpha3CountryCode};

fn main(
    certificate_registry_root: pub Field,
    certificate_registry_index: Field,
    certificate_registry_hash_path: [Field; ${CERTIFICATE_REGISTRY_HEIGHT}],
    certificate_tags: [Field; 3],
    salt: Field,
    country: Alpha3CountryCode,
    csc_pubkey_x: [u8; ${coordBytes}],
    csc_pubkey_y: [u8; ${coordBytes}],
    dsc_signature: [u8; ${coordBytes * 2}],
    tbs_certificate: [u8; ${tbsMaxLen}],
) -> pub Field {
    // Safety: length is verified by the hash + signature check
    let tbs_certificate_len = unsafe { utils::unsafe_get_asn1_element_length(tbs_certificate) };
    let (r, s): ([u8; ${coordBytes}], [u8; ${coordBytes}]) = split_array(dsc_signature);
    let msg_hash = ${hash}_and_check_data_to_sign(tbs_certificate, tbs_certificate_len);
    assert(
        verify_${curveFamily}_${curveName}(csc_pubkey_x, csc_pubkey_y, r, s, msg_hash),
        "ECDSA signature verification failed",
    );
    let pubkey_concat: [u8; ${coordBytes * 2}] = utils::concat_arrays(csc_pubkey_x, csc_pubkey_y);
    commit_to_dsc(
        certificate_registry_root, certificate_registry_index,
        certificate_registry_hash_path, certificate_tags,
        country, tbs_certificate, salt, pubkey_concat,
    )
}
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Generated circuit templates: ID data sig-check
// ─────────────────────────────────────────────────────────────────────────────

function idDataRsaTemplate(rsaType: RsaType, bitSize: number, tbsMaxLen: number, hash: HashAlgorithm): string {
  const modBytes = Math.ceil(bitSize / 8);
  return `// Auto-generated by circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_rsa_pubkey_in_tbs;
use sig_check_rsa::verify_rsa${bitSize}_${hash}_${rsaType};
use utils::types::{DG1Data, EContentData, SignedAttrsData};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey: [u8; ${modBytes}],
    dsc_pubkey_redc_param: [u8; ${modBytes + 1}],
    sod_signature: [u8; ${modBytes}],
    tbs_certificate: [u8; ${tbsMaxLen}],
    signed_attributes: SignedAttrsData,
    exponent: u32,
    e_content: EContentData,${rsaType === "pss" ? "\n    pss_salt_len: u32," : ""}
) -> pub Field {
    verify_rsa_pubkey_in_tbs(dsc_pubkey, tbs_certificate);
    // Safety: length is verified by the hash + signature check
    let signed_attributes_size = unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    assert(
        verify_rsa${bitSize}_${hash}_${rsaType}(
            dsc_pubkey, sod_signature, dsc_pubkey_redc_param, exponent,
            signed_attributes, signed_attributes_size,${rsaType === "pss" ? " pss_salt_len," : ""}
        ),
        "RSA signature verification failed",
    );
    commit_to_id(
        comm_in, salt_in, salt_out, dg1, tbs_certificate,
        sod_signature, signed_attributes,
        signed_attributes_size as Field, e_content,
    )
}
`;
}

function idDataEcdsaTemplate(curveFamily: string, curveName: string, bitSize: number, tbsMaxLen: number, hash: HashAlgorithm): string {
  const coordBytes = Math.ceil(bitSize / 8);
  return `// Auto-generated by circuit-builder.ts
use commitment::commit_to_id;
use data_check_tbs_pubkey::verify_ecdsa_pubkey_in_tbs;
use sig_check_common::${hash}_and_check_data_to_sign;
use sig_check_ecdsa::verify_${curveFamily}_${curveName};
use utils::{split_array, types::{DG1Data, EContentData, SignedAttrsData}};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salt_out: Field,
    dg1: DG1Data,
    dsc_pubkey_x: [u8; ${coordBytes}],
    dsc_pubkey_y: [u8; ${coordBytes}],
    sod_signature: [u8; ${coordBytes * 2}],
    tbs_certificate: [u8; ${tbsMaxLen}],
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
) -> pub Field {
    // Safety: length is verified by the hash + signature check
    let signed_attributes_size = unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    let (r, s): ([u8; ${coordBytes}], [u8; ${coordBytes}]) = split_array(sod_signature);
    let msg_hash = ${hash}_and_check_data_to_sign(signed_attributes, signed_attributes_size);
    let pubkey_concat: [u8; ${coordBytes * 2}] = utils::concat_arrays(dsc_pubkey_x, dsc_pubkey_y);
    verify_ecdsa_pubkey_in_tbs(pubkey_concat, tbs_certificate);
    assert(
        verify_${curveFamily}_${curveName}(dsc_pubkey_x, dsc_pubkey_y, r, s, msg_hash),
        "ECDSA signature verification failed",
    );
    commit_to_id(
        comm_in, salt_in, salt_out, dg1, tbs_certificate,
        sod_signature, signed_attributes,
        signed_attributes_size as Field, e_content,
    )
}
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Generated circuit template: Data integrity check
// ─────────────────────────────────────────────────────────────────────────────

function dataIntegrityCheckTemplate(saHash: HashAlgorithmExtended, dgHash: HashAlgorithmExtended): string {
  const dgBytes = getHashByteSize(dgHash);
  return `// Auto-generated by circuit-builder.ts
use commitment::commit_to_disclosure;
use data_check_integrity::{check_dg1_${dgHash}, check_signed_attributes_${saHash}, get_dg2_hash_from_econtent};
use utils::types::{EContentData, SignedAttrsData, SaltedValue};

fn main(
    comm_in: pub Field,
    salt_in: Field,
    salted_dg1: SaltedValue<95>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    signed_attributes: SignedAttrsData,
    e_content: EContentData,
    salted_private_nullifier: SaltedValue<32>,
) -> pub Field {
    // Safety: length is verified by the hash checks below
    let e_content_size = unsafe { utils::unsafe_get_asn1_element_length(e_content) };
    check_dg1_${dgHash}(salted_dg1.value, e_content, e_content_size);
    // Safety: length was committed in the ID data circuit
    let signed_attributes_size = unsafe { utils::unsafe_get_asn1_element_length(signed_attributes) };
    check_signed_attributes_${saHash}(signed_attributes, e_content, e_content_size);
    let dg2_hash: [u8; ${dgBytes}] = get_dg2_hash_from_econtent(e_content, e_content_size);
    commit_to_disclosure(
        comm_in, salt_in, salted_dg1, expiry_date_salt,
        dg2_hash_salt, dg2_hash,
        [${dgHash === "sha1" ? "1" : dgHash === "sha224" ? "2" : dgHash === "sha256" ? "3" : dgHash === "sha384" ? "4" : "5"}],
        signed_attributes, signed_attributes_size as Field,
        e_content, salted_private_nullifier,
    )
}
`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature algorithm configurations
// ─────────────────────────────────────────────────────────────────────────────

interface SigAlgorithm {
  type: "ecdsa" | "rsa";
  family: string;
  curveName?: string;
  bitSize: number;
}

const SIGNATURE_ALGORITHMS: SigAlgorithm[] = [
  // ECDSA - NIST
  { type: "ecdsa", family: "nist", curveName: "p192", bitSize: 192 },
  { type: "ecdsa", family: "nist", curveName: "p224", bitSize: 224 },
  { type: "ecdsa", family: "nist", curveName: "p256", bitSize: 256 },
  { type: "ecdsa", family: "nist", curveName: "p384", bitSize: 384 },
  { type: "ecdsa", family: "nist", curveName: "p521", bitSize: 521 },
  // ECDSA - Brainpool
  { type: "ecdsa", family: "brainpool", curveName: "192r1", bitSize: 192 },
  { type: "ecdsa", family: "brainpool", curveName: "224r1", bitSize: 224 },
  { type: "ecdsa", family: "brainpool", curveName: "256r1", bitSize: 256 },
  { type: "ecdsa", family: "brainpool", curveName: "384r1", bitSize: 384 },
  { type: "ecdsa", family: "brainpool", curveName: "512r1", bitSize: 512 },
  // RSA - PSS
  { type: "rsa", family: "pss", bitSize: 1024 },
  { type: "rsa", family: "pss", bitSize: 2048 },
  { type: "rsa", family: "pss", bitSize: 3072 },
  { type: "rsa", family: "pss", bitSize: 4096 },
  // RSA - PKCS#1v1.5
  { type: "rsa", family: "pkcs", bitSize: 1024 },
  { type: "rsa", family: "pkcs", bitSize: 2048 },
  { type: "rsa", family: "pkcs", bitSize: 3072 },
  { type: "rsa", family: "pkcs", bitSize: 4096 },
];

const TBS_MAX_LENGTHS = [700, 1000, 1200];
const HASH_ALGORITHMS: HashAlgorithm[] = ["sha1", "sha256", "sha384", "sha512"];
const HASH_ALGORITHMS_EXTENDED: HashAlgorithmExtended[] = ["sha1", "sha224", "sha256", "sha384", "sha512"];

// ─────────────────────────────────────────────────────────────────────────────
// Generator functions
// ─────────────────────────────────────────────────────────────────────────────

function generateDscCircuits() {
  console.log("Generating DSC sig-check circuits...");
  let count = 0;
  for (const alg of SIGNATURE_ALGORITHMS) {
    for (const tbsLen of TBS_MAX_LENGTHS) {
      for (const hash of HASH_ALGORITHMS) {
        if (hash === "sha512" && alg.type === "rsa" && alg.bitSize === 1024) continue;

        let noirSrc: string;
        let name: string;
        let folderPath: string;
        let deps: { name: string; path: string }[];

        if (alg.type === "rsa") {
          name = `sig_check_dsc_tbs_${tbsLen}_rsa_${alg.family}_${alg.bitSize}_${hash}`;
          folderPath = `src/noir/bin/sig-check/dsc/tbs_${tbsLen}/rsa/${alg.family}/${alg.bitSize}/${hash}`;
          noirSrc = dscRsaTemplate(alg.family as RsaType, alg.bitSize, tbsLen, hash);
          const lp = (s: string) => relLibPath(folderPath, s);
          deps = [
            { name: "sig_check_rsa", path: lp("sig-check/rsa") },
            { name: "utils", path: lp("utils") },
            { name: "commitment", path: lp("commitment/dsc-to-id") },
          ];
        } else {
          name = `sig_check_dsc_tbs_${tbsLen}_ecdsa_${alg.family}_${alg.curveName}_${hash}`;
          folderPath = `src/noir/bin/sig-check/dsc/tbs_${tbsLen}/ecdsa/${alg.family}/${alg.curveName}/${hash}`;
          noirSrc = dscEcdsaTemplate(alg.family, alg.curveName!, alg.bitSize, tbsLen, hash);
          const lp = (s: string) => relLibPath(folderPath, s);
          deps = [
            { name: "sig_check_ecdsa", path: lp("sig-check/ecdsa") },
            { name: "utils", path: lp("utils") },
            { name: "commitment", path: lp("commitment/dsc-to-id") },
            { name: "sig_check_common", path: lp("sig-check/common") },
          ];
        }

        const absFolder = path.join(CIRCUITS_ROOT, folderPath);
        const mainPath = path.join(absFolder, "src/main.nr");
        const tomlPath = path.join(absFolder, "Nargo.toml");
        ensureDir(mainPath);
        fs.writeFileSync(mainPath, noirSrc);
        fs.writeFileSync(tomlPath, nargoToml(name, deps));
        generatedCircuits.push({ name, path: folderPath });
        count++;
      }
    }
  }
  console.log(`  Generated ${count} DSC circuits`);
}

function generateIdDataCircuits() {
  console.log("Generating ID data sig-check circuits...");
  let count = 0;
  for (const alg of SIGNATURE_ALGORITHMS) {
    for (const tbsLen of TBS_MAX_LENGTHS) {
      for (const hash of HASH_ALGORITHMS) {
        if (hash === "sha512" && alg.type === "rsa" && alg.bitSize === 1024) continue;

        let noirSrc: string;
        let name: string;
        let folderPath: string;
        let deps: { name: string; path: string }[];

        if (alg.type === "rsa") {
          name = `sig_check_id_data_tbs_${tbsLen}_rsa_${alg.family}_${alg.bitSize}_${hash}`;
          folderPath = `src/noir/bin/sig-check/id-data/tbs_${tbsLen}/rsa/${alg.family}/${alg.bitSize}/${hash}`;
          noirSrc = idDataRsaTemplate(alg.family as RsaType, alg.bitSize, tbsLen, hash);
          const lp = (s: string) => relLibPath(folderPath, s);
          deps = [
            { name: "sig_check_rsa", path: lp("sig-check/rsa") },
            { name: "utils", path: lp("utils") },
            { name: "data_check_tbs_pubkey", path: lp("data-check/tbs-pubkey") },
            { name: "commitment", path: lp("commitment/dsc-to-id") },
          ];
        } else {
          name = `sig_check_id_data_tbs_${tbsLen}_ecdsa_${alg.family}_${alg.curveName}_${hash}`;
          folderPath = `src/noir/bin/sig-check/id-data/tbs_${tbsLen}/ecdsa/${alg.family}/${alg.curveName}/${hash}`;
          noirSrc = idDataEcdsaTemplate(alg.family, alg.curveName!, alg.bitSize, tbsLen, hash);
          const lp = (s: string) => relLibPath(folderPath, s);
          deps = [
            { name: "sig_check_ecdsa", path: lp("sig-check/ecdsa") },
            { name: "utils", path: lp("utils") },
            { name: "data_check_tbs_pubkey", path: lp("data-check/tbs-pubkey") },
            { name: "commitment", path: lp("commitment/dsc-to-id") },
            { name: "sig_check_common", path: lp("sig-check/common") },
          ];
        }

        const absFolder = path.join(CIRCUITS_ROOT, folderPath);
        const mainPath = path.join(absFolder, "src/main.nr");
        const tomlPath = path.join(absFolder, "Nargo.toml");
        ensureDir(mainPath);
        fs.writeFileSync(mainPath, noirSrc);
        fs.writeFileSync(tomlPath, nargoToml(name, deps));
        generatedCircuits.push({ name, path: folderPath });
        count++;
      }
    }
  }
  console.log(`  Generated ${count} ID data circuits`);
}

function generateDataIntegrityCheckCircuits() {
  console.log("Generating data integrity check circuits...");
  let count = 0;
  for (const saHash of HASH_ALGORITHMS_EXTENDED) {
    for (const dgHash of HASH_ALGORITHMS_EXTENDED) {
      const name = `data_check_integrity_sa_${saHash}_dg_${dgHash}`;
      const folderPath = `src/noir/bin/data-check/integrity/sa_${saHash}/dg_${dgHash}`;
      const noirSrc = dataIntegrityCheckTemplate(saHash, dgHash);
      const lp = (s: string) => relLibPath(folderPath, s);
      const deps = [
        { name: "data_check_integrity", path: lp("data-check/integrity") },
        { name: "commitment", path: lp("commitment/integrity-to-disclosure") },
        { name: "utils", path: lp("utils") },
      ];

      const absFolder = path.join(CIRCUITS_ROOT, folderPath);
      const mainPath = path.join(absFolder, "src/main.nr");
      const tomlPath = path.join(absFolder, "Nargo.toml");
      ensureDir(mainPath);
      fs.writeFileSync(mainPath, noirSrc);
      fs.writeFileSync(tomlPath, nargoToml(name, deps));
      generatedCircuits.push({ name, path: folderPath });
      count++;
    }
  }
  console.log(`  Generated ${count} integrity check circuits`);
}

// ─────────────────────────────────────────────────────────────────────────────
// Workspace Nargo.toml writer
// ─────────────────────────────────────────────────────────────────────────────

function generateWorkspaceToml() {
  const allBinPaths = [
    ...STATIC_CIRCUITS.map((c) => c.path),
    ...generatedCircuits.map((c) => c.path),
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
  const allCircuits = [...STATIC_CIRCUITS, ...generatedCircuits];
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
                resolve(); // continue compiling others
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
  generateDscCircuits();
  generateIdDataCircuits();
  generateDataIntegrityCheckCircuits();
  generateWorkspaceToml();

  const total = STATIC_CIRCUITS.length + generatedCircuits.length;
  console.log(`\nTotal: ${total} circuits generated`);
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
