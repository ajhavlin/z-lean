/-
Copyright (c) 2026 LeanStuff contributors. All rights reserved.
-/
import VectorCommitment.Properties.Probability.ROHasher
import VectorCommitment.Src.Merkle.Scheme

/-!
# `Verify^H` as an oracle computation (decision D1)

The **shared-oracle** form of Merkle verification. Rather than calling a stored
hasher (which would carry a complete oracle function — impossible to sample as a
`PMF`), it recomputes the root by *querying* the shared, lazily-sampled random
oracle, mirroring `MerkleCommitment.reconstructRoot` / `MerkleCommitment.check`
with `query (encode…)` in place of `hashLeaf`/`hashNodes`.

The ROM security experiments validate an adversary's break by running this
against the *same* `H` the adversary queried, so the winning event cannot be
decoupled from the oracle (spec §0.1, §2.1).
-/

namespace ROHasher

open OracleComp

/-- Walk the bottom-up copath, querying the oracle for each internal-node hash.
    Mirrors `MerkleCommitment.walkCopath`/`combineUp`: at position `pos` the
    accumulator is the left child iff `pos` is odd. -/
noncomputable def walkCopathOracle {κ : Nat} :
    Nat → List.Vector Bool κ → List (List.Vector Bool κ) →
      OracleComp (MerkleROSpec κ) (List.Vector Bool κ)
  | _,   acc, []          => pure acc
  | pos, acc, sib :: rest => do
      let children := if pos % 2 = 1 then [acc, sib] else [sib, acc]
      let parent ← query (encodeNodes children)
      walkCopathOracle ((pos - 1) / 2) parent rest

/-- Reconstruct a root from one `(i, value, salt, copath)` by querying the
    shared oracle. Mirrors `MerkleCommitment.reconstructRoot` (leaf position
    `n - 1 + i` for an `n`-leaf tree). -/
noncomputable def reconstructRootOracle {κ : Nat} (n i : Nat)
    (value salt : List ByteArray) (copath : List (List.Vector Bool κ)) :
    OracleComp (MerkleROSpec κ) (List.Vector Bool κ) := do
  let leaf ← query (encodeLeaf value salt)
  walkCopathOracle (n - 1 + i) leaf copath

/-- `Verify^H` for a Merkle opening of an `n`-leaf tree: every
    `(index, value, entry)` triple must reconstruct, via shared-oracle queries,
    to `root`. Mirrors `MerkleCommitment.check`. -/
noncomputable def checkOracle {κ : Nat} (n : Nat) (root : List.Vector Bool κ)
    (op : Opening (ROHasherValue κ)) (pf : OpeningProof (ROHasherValue κ)) :
    OracleComp (MerkleROSpec κ) Bool :=
  if op.indices.length ≠ op.values.length ∨ op.indices.length ≠ pf.entries.length then
    pure false
  else
    ((op.indices.zip op.values).zip pf.entries).foldlM
      (fun acc triple => do
        let ((i, value), (salt, copath)) := triple
        let r ← reconstructRootOracle n i value salt copath
        pure (acc && decide (r = root)))
      true

end ROHasher
