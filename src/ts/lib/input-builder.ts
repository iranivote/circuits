import { randomBytes, createHash } from "crypto";
import * as asn1js from "asn1js";
import type {
  PassportData,
  CircuitInputs,
  CertificateRegistryProof,
  HashAlgorithmExtended,
  RsaSigConfig,
  EcdsaSigConfig,
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

export function deterministicSalt(dg1: Uint8Array, label: string): string {
  const hash = createHash("sha256")
    .update(Buffer.from(dg1))
    .update(label)
    .digest()
    .subarray(0, 31);
  return BigInt("0x" + Buffer.from(hash).toString("hex")).toString();
}

export function deterministicNullifier(dg1: Uint8Array): Uint8Array {
  const hash = createHash("sha256")
    .update(Buffer.from(dg1))
    .update("private-nullifier")
    .digest();
  return new Uint8Array(hash);
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

function keySizeSelector(bitSize: number): number {
  if (bitSize <= 2048) return 0;
  if (bitSize <= 3072) return 1;
  return 2;
}

function hashTypeSelector(hash: string): number {
  const map: Record<string, number> = { sha1: 0, sha256: 1, sha384: 2, sha512: 3 };
  return map[hash] ?? 1;
}

function paddingTypeSelector(padding: string): number {
  return padding === "pss" ? 1 : 0;
}

function curveTypeSelector(curveName: string): number {
  if (curveName === "p256") return 0;
  if (curveName === "p384") return 1;
  return 2;
}

function rsaModulusBytes(bitSize: number): number {
  if (bitSize <= 2048) return 256;
  if (bitSize <= 3072) return 384;
  return 512;
}

function padEcdsaCoord(b: Uint8Array, coordBytes: number): Uint8Array {
  if (b.length === coordBytes) return b;
  if (b.length > coordBytes) return b.slice(b.length - coordBytes);
  const o = new Uint8Array(coordBytes);
  o.set(b, coordBytes - b.length);
  return o;
}

const ECDSA_CURVE_ORDER: Record<string, bigint> = {
  p192: 0x6277101735386680763835789423176059013767194773182842284081n,
  p224: 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3dn,
  p256: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  p384:
    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
  p521:
    0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409n,
  "192r1": 0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1n,
  "224r1": 0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939fn,
  "256r1": 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7n,
  "384r1":
    0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565n,
  "512r1":
    0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3n,
};

function parseEcdsaSignatureDer(
  der: Uint8Array,
  coordBytes: number,
  curveOrder?: bigint,
): { r: Uint8Array; s: Uint8Array } {
  const ab = (der.buffer as ArrayBuffer).slice(der.byteOffset, der.byteOffset + der.byteLength);
  const parsed = asn1js.fromBER(ab);
  if (parsed.offset === -1) throw new Error("Failed to parse ECDSA signature DER");

  const seq = parsed.result as asn1js.Sequence;
  const rInt = seq.valueBlock.value[0] as asn1js.Integer;
  const sInt = seq.valueBlock.value[1] as asn1js.Integer;

  let rBytes = new Uint8Array(rInt.valueBlock.valueHexView);
  let sBytes = new Uint8Array(sInt.valueBlock.valueHexView);

  if (rBytes[0] === 0 && rBytes.length > coordBytes) rBytes = rBytes.slice(1);
  if (sBytes[0] === 0 && sBytes.length > coordBytes) sBytes = sBytes.slice(1);

  if (curveOrder) {
    const sVal = BigInt("0x" + Buffer.from(sBytes).toString("hex"));
    const halfOrder = curveOrder >> 1n;
    if (sVal > halfOrder) {
      const sNorm = curveOrder - sVal;
      const hex = sNorm.toString(16).padStart(coordBytes * 2, "0");
      sBytes = new Uint8Array(Buffer.from(hex, "hex"));
    }
  }

  return { r: padEcdsaCoord(rBytes, coordBytes), s: padEcdsaCoord(sBytes, coordBytes) };
}

function ecdsaSodRs(
  sig: Uint8Array,
  coordBytes: number,
  curveName: string,
): { r: Uint8Array; s: Uint8Array } {
  if (sig.length > 0 && sig[0] === 0x30) {
    const order = ECDSA_CURVE_ORDER[curveName];
    return parseEcdsaSignatureDer(sig, coordBytes, order);
  }
  return {
    r: padEcdsaCoord(sig.slice(0, coordBytes), coordBytes),
    s: padEcdsaCoord(sig.slice(coordBytes, 2 * coordBytes), coordBytes),
  };
}

/** Inputs for `signup_verify_*` from synthetic {@link PassportData} (tests / CLI mocks). */
export function buildSignupVerifyInputsFromPassport(
  passport: PassportData,
  trustedRegistry: CertificateRegistryProof,
): CircuitInputs {
  const dg1 = passport.dg1;
  const dgHashId = hashAlgoId(passport.dgHashAlgorithm as HashAlgorithmExtended);
  const saHashId = hashAlgoId((passport.saHashAlgorithm ?? passport.dgHashAlgorithm) as HashAlgorithmExtended);
  const dg1Salt = deterministicSalt(dg1, "integrity-dg1");
  const expiryDateSalt = deterministicSalt(dg1, "integrity-expiry");
  const dg2HashSalt = deterministicSalt(dg1, "integrity-dg2-hash");
  const privateNullifierSalt = deterministicSalt(dg1, "integrity-nullifier-salt");
  const privateNullifier = deterministicNullifier(dg1);
  const tags = trustedRegistry.tags;

  const common = {
    trusted_dsc_root: trustedRegistry.root,
    certificate_registry_index: trustedRegistry.index,
    certificate_registry_hash_path: trustedRegistry.hashPath,
    certificate_tags: [String(tags[0]), String(tags[1]), String(tags[2])],
    salted_dg1: { salt: dg1Salt, value: zeroPad(dg1, DG1_MAX_LENGTH) },
    expiry_date_salt: expiryDateSalt,
    dg2_hash_salt: dg2HashSalt,
    signed_attributes: zeroPad(passport.signedAttributes, SIGNED_ATTRS_LENGTH),
    e_content: zeroPad(passport.eContent, ECONTENT_LENGTH),
    salted_private_nullifier: {
      salt: privateNullifierSalt,
      value: toNoirBytes(privateNullifier),
    },
    dg_hash_type: dgHashId,
    sa_hash_type: saHashId,
  };

  const sig = passport.sigConfig;
  if (sig.type === "rsa") {
    const rsa = sig as RsaSigConfig;
    const actualModBytes = rsaModulusBytes(rsa.bitSize);
    return {
      ...common,
      dsc_pubkey: zeroPad(passport.dscPubkey, 512),
      dsc_pubkey_redc_param: zeroPad(passport.dscPubkeyRedcParam!, 513),
      sod_signature: zeroPad(passport.sodSignature, 512),
      exponent: passport.rsaExponent ?? 65537,
      key_size: keySizeSelector(rsa.bitSize),
      hash_type: hashTypeSelector(rsa.hash ?? "sha256"),
      padding_type: paddingTypeSelector(rsa.padding),
      pss_salt_len: rsa.padding === "pss" ? (passport.pssSaltLen ?? 32) : 0,
      pubkey_len: actualModBytes,
    };
  }

  const ec = sig as EcdsaSigConfig;
  const coordBytes = Math.ceil(ec.bitSize / 8);
  const pubkey = passport.dscPubkey;
  const { r, s } = ecdsaSodRs(passport.sodSignature, coordBytes, ec.curveName);
  return {
    ...common,
    dsc_pubkey_x: zeroPad(pubkey.slice(0, coordBytes), 66),
    dsc_pubkey_y: zeroPad(pubkey.slice(coordBytes, 2 * coordBytes), 66),
    sod_sig_r: zeroPad(r, 66),
    sod_sig_s: zeroPad(s, 66),
    curve_type: curveTypeSelector(ec.curveName),
    hash_type: hashTypeSelector(ec.hash ?? "sha256"),
    pubkey_len: coordBytes * 2,
  };
}

// ---------------------------------------------------------------------------
// Disclosure circuit inputs (compare_age as example)
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
