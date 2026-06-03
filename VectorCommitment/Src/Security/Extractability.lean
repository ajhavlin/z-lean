/-
Copyright (c) 2026 LeanStuff contributors. All rights reserved.
-/
import VectorCommitment.Src.Trait
import VectorCommitment.Src.Security.Params
import Mathlib.Data.ENNReal.Basic
import Mathlib.Probability.ProbabilityMassFunction.Basic

/-!
# Straightline extractability — abstract security obligation

This file declares `HasStraightlineExtractor`. The property: there exists
an extractor that, reading only the model's "trace" (RO query log in the
ROM, internal-state record in the standard model), outputs a candidate
underlying string `m̃` such that every accepting opening the adversary
later produces is consistent with `m̃` — i.e. `value[i] = m̃[i]` at every
opened position.

This is strictly stronger than position binding. Position binding gives a
*partial* function on opened positions; extractability gives a *total*
string fixed before any opening. The total string is what an IOP/PCP
soundness reduction needs to quantify over.

"Straightline" = the extractor does not rewind the adversary; it reads
the model's trace once and outputs. This is what lets the extractor
compose with Fiat–Shamir (round-by-round knowledge soundness), per
[eprint 2024/1434, Untangling the Security of Kilian's Protocol].

Model-specific instances live under:
  * `VectorCommitment/Properties/Probability/Instances/ExtractabilityROM.lean`
  * `VectorCommitment/Properties/StandardModel/Instances/…`            (reserved)
-/

open VectorCommitment.Security (SecParams)

/-- Straightline extractability obligation in experiment form (D3+D5).
    A *search* game (baseline 0): the bound is on the failure probability. -/
class HasStraightlineExtractor (V : Type) [VectorCommitment V] where
  ExtractionAdversary : SecParams → Type
  /-- The extraction-failure experiment: distribution of the indicator
      "`A` produced an accepting opening whose value disagrees with the
      straightline (cache) extractor's output". -/
  extractionExperiment : ∀ {Θ : SecParams}, ExtractionAdversary Θ → PMF Bool
  /-- Upper bound; ROM Merkle: `Θ.q*(Θ.q-1)/2^(Θ.kappa+1)` (collision). -/
  extractionError : SecParams → ENNReal
  /-- The central guarantee: `Pr[extraction fails] ≤ extractionError Θ`. -/
  extraction_bound :
    ∀ {Θ : SecParams} (A : ExtractionAdversary Θ),
      (extractionExperiment A) true ≤ extractionError Θ
