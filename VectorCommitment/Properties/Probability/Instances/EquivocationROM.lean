/-
Copyright (c) 2026 LeanStuff contributors. All rights reserved.
-/
import VectorCommitment.Src.Security.Equivocation
import VectorCommitment.Src.Merkle.Instance
import VectorCommitment.Properties.Probability.ROHasher
import VectorCommitment.Properties.Probability.Collision
import VectorCommitment.Properties.Theorems.Equivocation

/-!
# ROM instance: equivocation for RO-derived Merkle commitments

Discharges `HasEquivocation (MerkleCommitment (ROHasherValue κ) S)` in
the *programmable* classical random-oracle model.

This file is not a trapdoor-equivocable VC proof. It is the simulator
side of the usual ROM zero-knowledge argument: the simulator may program
oracle values that the adversary has not already queried. In the
standard model, and in a non-programmable ROM statement, ordinary Merkle
commitments should not receive an equivocation instance.

## What this instance asserts

There exists a simulator pair `(RootSim, OpeningSim)`:

* `RootSim` outputs a uniformly-random placeholder root, no message
  committed.
* `OpeningSim`, given the placeholder root and an opening request
  `(I, m[I])`, *programs* the RO at the path/copath nodes so the
  reconstruction walks up to the placeholder root.

The (Real, Ideal) distributions are statistically close with bound

    ε_equiv ≤ Q · d · q / 2^κ + Q² / 2^s

where `Q` is the number of openings, `d = depth(S)`, `q` the
adversary's RO query budget, `s` the salt size. The first term is the
programming-collision event: the adversary already queried a node-input
the simulator wants to program. The second is salt freshness.

## Status

The legacy theorem in `Properties/Theorems/Equivocation.lean` currently
has no probabilistic content. Closing the ROM instance here requires
*first* extending the lazy-sampling RO model in
`Properties/Probability/RandomOracle.lean` with a **programmable**
variant — an `OracleComp` operation that pre-populates entries in
`QueryLog` before sampling continues from there. The skeleton is
straightforward; the rigorous coupling argument is the work.

## Reduction sketch

1. Build the simulator as an `OracleComp` that produces a fresh root,
   then on each opening request: pick a fresh salt, set leaf-input →
   placeholder digest, and program internal-node inputs along the path.
2. The bad event is "the adversary's distinguishing advantage."
3. Decompose into the union of: (a) programming-failure (programmed
   point already queried) and (b) salt-collision.
4. Both bounded by `Probability.birthdayBound_kappa` at the appropriate
   parameters.

## Open work for the student

This is the hardest of the four ROM instances. It depends on:

* **A programmable RO extension** to `OracleComp` — currently the model
  only supports lazy sampling, no programming. Suggested extension:
  expose `OracleComp.program : Domain → Range → OracleComp _ Unit` that
  inserts into the cache; prove that "for unqueried inputs, programmed
  ≡ lazy-sample" up to `q / |Range|` per programmed point.

* **The simulator construction** itself, plus the coupling argument
  showing real ≈ ideal.

* **Replacing the legacy `mt_equivocation` placeholder** in
  `Properties/Theorems/Equivocation.lean` with a real distributional
  statement.
-/

namespace VectorCommitment.Probability.Instances

variable (κ : Nat) (S : Type) [MerkleShape S]
  [Nonempty (MerkleCommitment (ROHasher.ROHasherValue κ) S)]

/-- Equivocation for the RO-derived Merkle commitment. -/
noncomputable instance :
    HasSimulationEquivocation (MerkleCommitment (ROHasher.ROHasherValue κ) S) where
  SimAdversary := fun _ =>
    OracleComp (ROHasher.MerkleROSpec κ) Bool
  -- TODO(M6): programmable-RO simulator + coupling lemma; pending.
  simExperiment := sorry
  simError := fun Θ => Probability.collisionBound κ Θ.q
  sim_bound := sorry

end VectorCommitment.Probability.Instances
