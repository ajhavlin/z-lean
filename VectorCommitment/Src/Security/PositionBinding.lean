/-
Copyright (c) 2026 LeanStuff contributors. All rights reserved.
-/
import VectorCommitment.Src.Trait
import VectorCommitment.Src.Security.Params
import Mathlib.Data.ENNReal.Basic
import Mathlib.Probability.ProbabilityMassFunction.Basic

/-!
# Position binding — abstract security obligation

This file declares the model-agnostic typeclass `HasPositionBinding`.
The property: no adversary, in any computational model the instance
specifies, can produce two distinct accepting openings of the same
position of a single commitment.

A security model discharges this class by:
  * supplying an `Adversary` type capturing its computational shape
    (ROM: an `OracleComp` returning a candidate break;
     standard model: a runtime-bounded reduction to an assumption),
  * defining the adversary's binding advantage,
  * exhibiting an `Error` bound and proving the advantage is below it.

Model-specific instances live under:
  * `VectorCommitment/Properties/Probability/Instances/BindingROM.lean`
  * `VectorCommitment/Properties/StandardModel/Instances/BindingCR.lean`  (reserved)

Higher-level protocol theorems (Kilian's Theorem 5.1, BCS soundness,
IOPP compilations) consume this class abstractly and stay
model-neutral.
-/

namespace VectorCommitment.Security

open VectorCommitment

/-- A position-binding break: a commitment together with two singleton
    openings of the same position that disagree on the revealed value.

    Each opening is `(value, proof)`; the values differ; the verifier
    accepts both. Validity against a specific `vk` is captured by
    `BindingBreak.IsValid` below.

    A break does not by itself carry the verifier key — the binding game
    samples the key and then asks the adversary to produce a break that
    is valid against it. -/
structure BindingBreak (V : Type) [VectorCommitment V] where
  commitment : Commitment V
  index      : Index V
  value₀     : Alphabet V
  value₁     : Alphabet V
  proof₀     : Proof V
  proof₁     : Proof V

/-- A break is *valid* against verifier key `vk` when both singleton
    openings pass `check` and reveal distinct values. -/
def BindingBreak.IsValid {V : Type} [VectorCommitment V]
    (vk : VerifierKey V) (b : BindingBreak V) : Prop :=
  b.value₀ ≠ b.value₁ ∧
  check vk b.commitment [b.index] [b.value₀] b.proof₀ = true ∧
  check vk b.commitment [b.index] [b.value₁] b.proof₁ = true

end VectorCommitment.Security

open VectorCommitment.Security (SecParams)

/-- Position-binding obligation in **experiment form** (decisions D1+D5,
    spec §0.1–§0.2, §2.1).

    The advantage is *pinned* to an explicit experiment `bindingExperiment`
    returning the distribution of the win-bit: it is never a free field an
    instance could set to `0`. The experiment is run over the parameter
    tuple `Θ = (λ,κ,s,ℓ,Q,q)`; for a transparent-setup ROM scheme it samples
    the shared oracle `H` and runs `Verify^H` against the *same* `H` the
    adversary queries (so the winning event cannot be decoupled from `H`).

    An `instance` for a concrete commitment type `V` under a chosen security
    model discharges the four fields below. -/
class HasPositionBinding (V : Type) [VectorCommitment V] where
  /-- The adversary type at parameters `Θ`. ROM: an `OracleComp` over the
      RO spec returning a `BindingBreak V`; standard model: a runtime-bounded
      reduction to an assumption. -/
  BindingAdversary : SecParams → Type
  /-- The binding **experiment**: the distribution of the Boolean win-bit
      when `A` is run against the model's sampled oracle and its `Verify^H`.
      The advantage is `bindingExperiment A true = Pr[A wins]`. -/
  bindingExperiment : ∀ {Θ : SecParams}, BindingAdversary Θ → PMF Bool
  /-- The model-specific upper bound; may depend on any component of `Θ`.
      ROM Merkle: `q * (q - 1) / 2 ^ (κ + 1)` (birthday). -/
  bindingError : SecParams → ENNReal
  /-- The central guarantee: `Pr[A wins] ≤ bindingError Θ`. -/
  binding_bound :
    ∀ {Θ : SecParams} (A : BindingAdversary Θ),
      (bindingExperiment A) true ≤ bindingError Θ
