/-
Copyright (c) 2026 LeanStuff contributors. All rights reserved.
-/
import VectorCommitment.Src.Trait
import VectorCommitment.Src.Security.Params
import Mathlib.Data.ENNReal.Basic
import Mathlib.Probability.ProbabilityMassFunction.Basic

/-!
# Equivocation — abstract security obligation

This file declares `HasEquivocation`. In this module the name means a
*model-supplied simulator* property: there exists a simulator pair
`(RootSim, OpeningSim)` — operating with the resource supplied by the
model, such as a programmable RO for a ROM Merkle proof or a trapdoor key
for an algebraic commitment — such that for every adversary the two
distributions

  Real:  (C, td) ← Commit(m);  π ← Open(td, I);   output (C, m[I], π)
  Ideal: (C, st) ← RootSim();  π ← OpeningSim(st, I, m[I]);  output (...)

are computationally close.

This is strictly stronger than hiding. A hiding commitment merely
doesn't leak `m`; an equivocable commitment is one the simulator can
commit *without knowing `m`* and later open arbitrarily. The stronger
property is what a zero-knowledge argument's simulator uses: it doesn't
hold the witness, so it commits blind and opens to whatever the IOPP
simulator hands it.

This is not the same notion as a trapdoor-equivocable vector commitment.
Ordinary Merkle commitments do not have a setup trapdoor that lets the
committer later open one root to arbitrary messages. What they may have,
in a programmable classical ROM, is a simulator argument that programs
unqueried oracle points. Hash-based commitments in the standard model
therefore do not get this instance. Algebraic commitments such as
Pedersen or KZG may satisfy a trapdoor version under their own
assumptions.

Model-specific instances live under:
  * `VectorCommitment/Properties/Probability/Instances/EquivocationROM.lean`
  * `VectorCommitment/Properties/StandardModel/Instances/EquivocationPedersen.lean`
        (reserved — would require Pedersen, not Merkle)
-/

open VectorCommitment.Security (SecParams)

/-- Programmable-ROM **simulation** obligation in experiment form (D4+D5,
    spec §9.8) — renamed from `HasEquivocation` to avoid colliding with the
    §9 *trapdoor* equivocability that Merkle provably lacks (EQ3). This is a
    real-or-ideal distinguishing game using a *programmable* oracle. -/
class HasSimulationEquivocation (V : Type) [VectorCommitment V] where
  SimAdversary : SecParams → Type
  /-- The real-or-ideal distinguishing experiment: distribution of the
      indicator "distinguisher guessed the world (Real vs Ideal) correctly". -/
  simExperiment : ∀ {Θ : SecParams}, SimAdversary Θ → PMF Bool
  /-- Upper bound; ROM Merkle: `Θ.Q*d*Θ.q/2^Θ.kappa + Θ.Q^2/2^Θ.s`. -/
  simError : SecParams → ENNReal
  /-- Distinguishing guarantee: `Pr[guess correct] ≤ 1/2 + simError Θ`. -/
  sim_bound :
    ∀ {Θ : SecParams} (A : SimAdversary Θ),
      (simExperiment A) true ≤ 1 / 2 + simError Θ
