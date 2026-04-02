import { randomBytes, createHash } from "crypto";
import type {
  PassportData,
  CircuitInputs,
  CertificateRegistryProof,
  HashAlgorithm,
  HashAlgorithmExtended,
  RsaSigConfig,
} from "./types.js";

// ---------------------------------------------------------------------------
// Circuit constants (must match utils/src/constants.nr)
// ---------------------------------------------------------------------------

const DG1_MAX_LENGTH = 95;
const SIGNED_ATTRS_LENGTH = 256;
const ECONTENT_LENGTH = 512;
const CERTIFICATE_REGISTRY_HEIGHT = 16;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Pad or truncate a Uint8Array to exactly `len` bytes (zero-padded) */
function zeroPad(data: Uint8Array, len: number): number[] {
  const result = new Array(len).fill(0);
  for (let i = 0; i < Math.min(data.length, len); i++) {
    result[i] = data[i];
  }
  return result;
}

/** Convert a Uint8Array to a Noir-compatible array of numbers */
function toNoirBytes(data: Uint8Array): number[] {
  return Array.from(data);
}

/** Generate a random BN254 field element as a decimal string */
export function randomSalt(): string {
  const bytes = randomBytes(31);
  const n = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  // BN254 scalar field is ~2^254, so 31 random bytes (248 bits) is safe
  return n.toString();
}

/** Convert a 3-letter country code to a Noir `str<3>` representation */
function countryToNoir(code: string): string {
  if (code.length !== 3) throw new Error(`Expected 3-letter country code, got: ${code}`);
  return code;
}

function hashAlgoId(h: HashAlgorithmExtended): number {
  const map: Record<string, number> = { sha1: 1, sha224: 2, sha256: 3, sha384: 4, sha512: 5 };
  return map[h] ?? 0;
}

// ---------------------------------------------------------------------------
// DG1 construction from MRZ
// ---------------------------------------------------------------------------

const DG1_HEADER = [0x61, 0x5b, 0x5f, 0x1f, 0x58];

/** Build DG1 bytes from two MRZ lines (TD3 passport format) */
export function buildDg1FromMrz(line1: string, line2: string): Uint8Array {
  if (line1.length !== 44) throw new Error(`MRZ line 1 must be 44 chars, got ${line1.length}`);
  if (line2.length !== 44) throw new Error(`MRZ line 2 must be 44 chars, got ${line2.length}`);

  const mrz = Buffer.from(line1 + line2, "ascii");
  const dg1 = Buffer.alloc(93);
  Buffer.from(DG1_HEADER).copy(dg1, 0);
  mrz.copy(dg1, 5);
  return new Uint8Array(dg1);
}

/** Extract the issuing country from MRZ (positions 2-4 in the MRZ, offset 7-9 in DG1) */
export function extractCountryFromDg1(dg1: Uint8Array): string {
  return String.fromCharCode(dg1[7], dg1[8], dg1[9]);
}

// ---------------------------------------------------------------------------
// Stage 1: DSC sig-check inputs
// ---------------------------------------------------------------------------

export interface DscInputOptions {
  passport: PassportData;
  registryProof: CertificateRegistryProof;
  salt?: string;
}

export function buildDscInputs(opts: DscInputOptions): CircuitInputs {
  const { passport, registryProof } = opts;
  const salt = opts.salt ?? randomSalt();
  const sig = passport.sigConfig;

  if (sig.type !== "rsa") {
    throw new Error("ECDSA DSC inputs not yet implemented");
  }

  const rsa = sig as RsaSigConfig;
  const modBytes = Math.ceil(rsa.bitSize / 8);
  const tbsBucket = passport.tbsCertificate.length;

  return {
    certificate_registry_root: registryProof.root,
    certificate_registry_index: registryProof.index,
    certificate_registry_hash_path: registryProof.hashPath,
    certificate_tags: registryProof.tags,
    salt,
    country: extractCountryFromDg1(passport.dg1),
    tbs_certificate: zeroPad(passport.tbsCertificate, tbsBucket <= 700 ? 700 : tbsBucket <= 1000 ? 1000 : 1200),
    csc_pubkey: zeroPad(passport.cscPubkey!, modBytes),
    csc_pubkey_redc_param: zeroPad(passport.cscPubkeyRedcParam!, modBytes + 1),
    dsc_signature: zeroPad(passport.cscSignature!, modBytes),
    exponent: passport.rsaExponent ?? 65537,
    ...(rsa.padding === "pss" ? { pss_salt_len: passport.pssSaltLen ?? 32 } : {}),
    // Pass-through metadata for chaining
    _salt: salt,
  };
}

// ---------------------------------------------------------------------------
// Stage 2: ID data sig-check inputs
// ---------------------------------------------------------------------------

export interface IdDataInputOptions {
  passport: PassportData;
  /** Output commitment from DSC stage */
  dscCommitment: string;
  saltIn?: string;
  saltOut?: string;
}

export function buildIdDataInputs(opts: IdDataInputOptions): CircuitInputs {
  const { passport } = opts;
  const saltIn = opts.saltIn ?? randomSalt();
  const saltOut = opts.saltOut ?? randomSalt();
  const sig = passport.sigConfig;

  if (sig.type !== "rsa") {
    throw new Error("ECDSA ID data inputs not yet implemented");
  }

  const rsa = sig as RsaSigConfig;
  const modBytes = Math.ceil(rsa.bitSize / 8);

  return {
    comm_in: opts.dscCommitment,
    salt_in: saltIn,
    salt_out: saltOut,
    dg1: zeroPad(passport.dg1, DG1_MAX_LENGTH),
    dsc_pubkey: zeroPad(passport.dscPubkey, modBytes),
    dsc_pubkey_redc_param: zeroPad(passport.dscPubkeyRedcParam!, modBytes + 1),
    sod_signature: zeroPad(passport.sodSignature, modBytes),
    tbs_certificate: zeroPad(passport.tbsCertificate,
      passport.tbsCertificate.length <= 700 ? 700 : passport.tbsCertificate.length <= 1000 ? 1000 : 1200),
    signed_attributes: zeroPad(passport.signedAttributes, SIGNED_ATTRS_LENGTH),
    exponent: passport.rsaExponent ?? 65537,
    e_content: zeroPad(passport.eContent, ECONTENT_LENGTH),
    ...(rsa.padding === "pss" ? { pss_salt_len: passport.pssSaltLen ?? 32 } : {}),
    _saltOut: saltOut,
  };
}

// ---------------------------------------------------------------------------
// Stage 3: Data integrity check inputs
// ---------------------------------------------------------------------------

export interface IntegrityInputOptions {
  passport: PassportData;
  /** Output commitment from ID data stage */
  idDataCommitment: string;
  saltIn?: string;
  dg1Salt?: string;
  expiryDateSalt?: string;
  dg2HashSalt?: string;
  privateNullifierSalt?: string;
}

export function buildIntegrityInputs(opts: IntegrityInputOptions): CircuitInputs {
  const { passport } = opts;
  const saltIn = opts.saltIn ?? randomSalt();
  const dg1Salt = opts.dg1Salt ?? randomSalt();
  const expiryDateSalt = opts.expiryDateSalt ?? randomSalt();
  const dg2HashSalt = opts.dg2HashSalt ?? randomSalt();
  const privateNullifierSalt = opts.privateNullifierSalt ?? randomSalt();

  // The private nullifier is derived from passport data -- for now use a random placeholder
  const privateNullifier = new Uint8Array(32);
  randomBytes(32).copy(Buffer.from(privateNullifier.buffer));

  return {
    comm_in: opts.idDataCommitment,
    salt_in: saltIn,
    salted_dg1: {
      salt: dg1Salt,
      value: zeroPad(passport.dg1, DG1_MAX_LENGTH),
    },
    expiry_date_salt: expiryDateSalt,
    dg2_hash_salt: dg2HashSalt,
    signed_attributes: zeroPad(passport.signedAttributes, SIGNED_ATTRS_LENGTH),
    e_content: zeroPad(passport.eContent, ECONTENT_LENGTH),
    salted_private_nullifier: {
      salt: privateNullifierSalt,
      value: toNoirBytes(privateNullifier),
    },
    // Carry forward salts for the disclosure stage
    _dg1Salt: dg1Salt,
    _expiryDateSalt: expiryDateSalt,
    _dg2HashSalt: dg2HashSalt,
    _privateNullifierSalt: privateNullifierSalt,
    _privateNullifier: toNoirBytes(privateNullifier),
  };
}

// ---------------------------------------------------------------------------
// Stage 4: Disclosure circuit inputs (compare_age as example)
// ---------------------------------------------------------------------------

export interface AgeDisclosureInputOptions {
  passport: PassportData;
  /** Output commitment from integrity stage */
  integrityCommitment: string;
  currentDate: bigint;
  minAge: number;
  maxAge: number;
  serviceScope: string;
  serviceSubscope: string;
  nullifierSecret?: string;
  /** Salts from integrity stage */
  salts: {
    dg1Salt: string;
    expiryDateSalt: string;
    dg2HashSalt: string;
    privateNullifierSalt: string;
    privateNullifier: number[];
  };
}

export function buildAgeDisclosureInputs(opts: AgeDisclosureInputOptions): CircuitInputs {
  const { passport, salts } = opts;
  const nullifierSecret = opts.nullifierSecret ?? "0";

  // Extract expiry date bytes from DG1 (offset 70-75 in the MRZ = offset 75-80 in DG1 with 5-byte header)
  const expiryBytes = zeroPad(passport.dg1.slice(70, 76), 6);

  // DG2 hash -- we don't have DG2 in PassportData, use a placeholder
  const dg2Hash = new Array(64).fill(0);
  const dg2HashType = [hashAlgoId(passport.dgHashAlgorithm as HashAlgorithmExtended)];

  return {
    comm_in: opts.integrityCommitment,
    current_date: opts.currentDate.toString(),
    salted_private_nullifier: {
      salt: salts.privateNullifierSalt,
      value: salts.privateNullifier,
    },
    salted_expiry_date: {
      salt: salts.expiryDateSalt,
      value: expiryBytes,
    },
    salted_dg1: {
      salt: salts.dg1Salt,
      value: zeroPad(passport.dg1, DG1_MAX_LENGTH),
    },
    salted_dg2_hash: {
      salt: salts.dg2HashSalt,
      value: dg2Hash,
    },
    salted_dg2_hash_type: {
      salt: salts.dg2HashSalt,
      value: dg2HashType,
    },
    min_age_required: opts.minAge,
    max_age_required: opts.maxAge,
    nullifier_secret: nullifierSecret,
    service_scope: opts.serviceScope,
    service_subscope: opts.serviceSubscope,
  };
}

// ---------------------------------------------------------------------------
// Mock certificate registry (for testing without a real Merkle tree)
// ---------------------------------------------------------------------------

export function buildMockRegistryProof(): CertificateRegistryProof {
  return {
    root: "0",
    index: "0",
    hashPath: new Array(CERTIFICATE_REGISTRY_HEIGHT).fill("0"),
    tags: ["0", "0", "0"],
  };
}
