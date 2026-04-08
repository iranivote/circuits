// ---------------------------------------------------------------------------
// Circuit selection
// ---------------------------------------------------------------------------

export type HashAlgorithm = "sha1" | "sha256" | "sha384" | "sha512";
export type HashAlgorithmExtended = "sha1" | "sha224" | "sha256" | "sha384" | "sha512";
export type RsaPadding = "pkcs" | "pss";
export type EcdsaCurveFamily = "nist" | "brainpool";

export interface RsaSigConfig {
  type: "rsa";
  padding: RsaPadding;
  bitSize: 1024 | 2048 | 3072 | 4096;
  hash?: string;
}

export interface EcdsaSigConfig {
  type: "ecdsa";
  family: EcdsaCurveFamily;
  curveName: string;
  bitSize: number;
  hash?: string;
}

export type SignatureConfig = RsaSigConfig | EcdsaSigConfig;

export interface CircuitSelector {
  stage: "signup" | "disclosure";
  sig?: SignatureConfig;
  disclosureType?: string;
}

// ---------------------------------------------------------------------------
// Compiled circuit artifact (the JSON produced by `nargo compile`)
// ---------------------------------------------------------------------------

export interface CompiledCircuit {
  bytecode: string;
  abi: {
    parameters: Array<{
      name: string;
      type: Record<string, unknown>;
      visibility: "private" | "public";
    }>;
    return_type: Record<string, unknown> | null;
  };
}

// ---------------------------------------------------------------------------
// Raw passport data (as received from the NFC chip / client)
// ---------------------------------------------------------------------------

export interface PassportData {
  /** MRZ line 1 (44 chars for TD3 passports) */
  mrzLine1: string;
  /** MRZ line 2 (44 chars for TD3 passports) */
  mrzLine2: string;
  /** DG1 bytes including 5-byte header (93 bytes total for TD3) */
  dg1: Uint8Array;
  /** SOD as raw DER bytes */
  sod: Uint8Array;
  /** TBS certificate extracted from the DS cert inside the SOD */
  tbsCertificate: Uint8Array;
  /** DSC public key (modulus for RSA, concatenated x||y for ECDSA) */
  dscPubkey: Uint8Array;
  /** For RSA: Barrett reduction parameter for the modulus */
  dscPubkeyRedcParam?: Uint8Array;
  /** SOD signature bytes */
  sodSignature: Uint8Array;
  /** Signed attributes from the SOD CMS structure */
  signedAttributes: Uint8Array;
  /** eContent (LDS Security Object) from the SOD */
  eContent: Uint8Array;
  /** CSC (country signing CA) public key for DSC stage */
  cscPubkey?: Uint8Array;
  /** CSC Barrett reduction param (RSA only) */
  cscPubkeyRedcParam?: Uint8Array;
  /** CSC signature over the TBS certificate */
  cscSignature?: Uint8Array;
  /** DSC's signature algorithm (used for SOD stage) */
  sigConfig: SignatureConfig;
  /** CSCA's signature algorithm (used for DSC stage). May differ from sigConfig. */
  cscSigConfig?: SignatureConfig;
  /** Hash algorithm used for data groups */
  dgHashAlgorithm: HashAlgorithm;
  /** Hash algorithm used for signed attributes */
  saHashAlgorithm: HashAlgorithm;
  /** RSA exponent (usually 65537) */
  rsaExponent?: number;
  /** PSS salt length */
  pssSaltLen?: number;
}

// ---------------------------------------------------------------------------
// Certificate registry (Merkle tree of trusted CSCAs)
// ---------------------------------------------------------------------------

export interface CertificateRegistryProof {
  root: string;
  index: string;
  hashPath: string[];
  tags: [string, string, string];
}

// ---------------------------------------------------------------------------
// Proof chain inputs / outputs
// ---------------------------------------------------------------------------

/** Salted value as expected by Noir circuits */
export interface SaltedValue<N extends number = number> {
  salt: string;
  value: string[];
}

/** Full input for a single circuit stage */
export type CircuitInputs = Record<string, unknown>;

/** A generated proof + public return values */
export interface ProofResult {
  proof: Uint8Array;
  publicInputs: string[];
}

/** Bundle of all proofs for the full passport verification chain */
export interface ProofChainBundle {
  signupProof: ProofResult;
  disclosureProof?: ProofResult;
  commitment: string;
  nullifier?: string;
  paramCommitment?: string;
  circuitNames: {
    signup: string;
    disclosure?: string;
  };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export interface VerifyResult {
  valid: boolean;
  error?: string;
  commitment?: string;
  nullifier?: string;
  paramCommitment?: string;
}
