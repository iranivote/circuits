import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import type { CompiledCircuit, ProofResult, CircuitInputs } from "./types.js";

let _bbInstance: Barretenberg | null = null;

/**
 * Get or create the shared Barretenberg instance.
 * Reuse across multiple proof operations for efficiency.
 */
export async function getBb(): Promise<Barretenberg> {
  if (!_bbInstance) {
    _bbInstance = await Barretenberg.new();
  }
  return _bbInstance;
}

export async function generateProof(
  circuit: CompiledCircuit,
  inputs: CircuitInputs,
): Promise<ProofResult> {
  const noir = new Noir(circuit as any);
  const { witness } = await noir.execute(inputs as any);

  const bb = await getBb();
  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  const proofData = await backend.generateProof(witness);
  return {
    proof: proofData.proof,
    publicInputs: proofData.publicInputs,
  };
}

export async function verifyProof(
  circuit: CompiledCircuit,
  proof: Uint8Array,
  publicInputs: string[],
): Promise<boolean> {
  const bb = await getBb();
  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  return backend.verifyProof({ proof, publicInputs });
}

export async function getVerificationKey(
  circuit: CompiledCircuit,
): Promise<Uint8Array> {
  const bb = await getBb();
  const backend = new UltraHonkBackend(circuit.bytecode, bb);
  return backend.getVerificationKey();
}

/**
 * Execute a circuit without generating a proof -- useful for testing inputs
 * or extracting the return value before committing to a full proof.
 */
export async function executeCircuit(
  circuit: CompiledCircuit,
  inputs: CircuitInputs,
): Promise<{ witness: Uint8Array; returnValue: unknown }> {
  const noir = new Noir(circuit as any);
  return noir.execute(inputs as any);
}

// ---------------------------------------------------------------------------
// NoirProver -- cached backend for repeated proofs on the same circuit
// ---------------------------------------------------------------------------

export class NoirProver {
  private noir: Noir;
  private backend: UltraHonkBackend | null = null;
  private bbPromise: Promise<Barretenberg>;

  constructor(private circuit: CompiledCircuit) {
    this.noir = new Noir(circuit as any);
    this.bbPromise = getBb();
  }

  private async getBackend(): Promise<UltraHonkBackend> {
    if (!this.backend) {
      const bb = await this.bbPromise;
      this.backend = new UltraHonkBackend(this.circuit.bytecode, bb);
    }
    return this.backend;
  }

  async generateProof(inputs: CircuitInputs): Promise<ProofResult> {
    const { witness } = await this.noir.execute(inputs as any);
    const backend = await this.getBackend();
    const proofData = await backend.generateProof(witness);
    return {
      proof: proofData.proof,
      publicInputs: proofData.publicInputs,
    };
  }

  async verifyProof(proof: Uint8Array, publicInputs: string[]): Promise<boolean> {
    const backend = await this.getBackend();
    return backend.verifyProof({ proof, publicInputs });
  }

  async getVerificationKey(): Promise<Uint8Array> {
    const backend = await this.getBackend();
    return backend.getVerificationKey();
  }
}

/** Shut down the shared Barretenberg instance (for clean process exit) */
export async function destroyBb(): Promise<void> {
  if (_bbInstance) {
    await _bbInstance.destroy();
    _bbInstance = null;
  }
}
