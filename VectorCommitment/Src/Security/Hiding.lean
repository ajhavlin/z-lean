/-
Copyright (c) 2026 LeanStuff contributors. All rights reserved.
-/
import VectorCommitment.Src.Trait
import VectorCommitment.Src.Security.Params
import Mathlib.Data.ENNReal.Basic
import Mathlib.Probability.ProbabilityMassFunction.Basic

/-!
# Hiding — abstract security obligation

This file declares `HasHiding`. The property: a commitment, together with
openings at a chosen index set, reveals nothing about the values at
*unopened* positions beyond what those openings disclose.

The standard distinguishing game:
  1. Adversary picks two messages `m₀, m₁` of the same length and an
     index set `I` it wants opened.
  2. Challenger samples `b ←$ {0,1}`, commits to `m_b`, opens at `I`.
  3. Adversary, given the commitment + openings, outputs a guess `b'`.
  4. Advantage = `|Pr[b' = b] − 1/2|`.

The bound is "bounded-query hiding": hiding holds as long as the
adversary sees at most some `Q` openings (which becomes the IOPP's query
complexity in the compiled protocol). The bound captures both `Q` (the
number of openings) and `q` (the underlying oracle/computational budget).

Model-specific instances live under:
  * `VectorCommitment/Properties/Probability/Instances/HidingROM.lean`
  * `VectorCommitment/Properties/StandardModel/Instances/…`        (reserved)
-/

open VectorCommitment.Security (SecParams)

/-- Hiding obligation in experiment form (D1+D2+D5). Hiding is a *salt-space*
    distinguishing notion: the error may name `s, ℓ, Q` from `Θ`, and the
    instance precondition `s ≥ 1` keeps deterministic schemes out of scope. -/
class HasHiding (V : Type) [VectorCommitment V] where
  HidingAdversary : SecParams → Type
  /-- The bit-guessing hiding experiment: distribution of the indicator
      `b' = b`. Advantage `= (hidingExperiment A) true = Pr[b' = b]`. -/
  hidingExperiment : ∀ {Θ : SecParams}, HidingAdversary Θ → PMF Bool
  /-- Salt-space upper bound; ROM Merkle: `Θ.ell*Θ.q/2^Θ.s + Θ.Q^2/2^Θ.s`. -/
  hidingError : SecParams → ENNReal
  /-- Distinguishing guarantee: `Pr[b' = b] ≤ 1/2 + hidingError Θ`. -/
  hiding_bound :
    ∀ {Θ : SecParams} (A : HidingAdversary Θ),
      (hidingExperiment A) true ≤ 1 / 2 + hidingError Θ
