/-
Copyright (c) 2026 LeanStuff contributors. All rights reserved.
-/

/-!
# Security parameter tuple Θ

The shared parameter tuple every security notion is quantified over, per
`wiki/concepts/vc-security-notions.md` §0.2 (decision D5). Pinning every
notion's advantage to an explicit experiment over this tuple is what prevents
a free `advantage` field (which an instance could set to `0`, discharging the
bound while proving nothing) and lets each error term name exactly the
parameters it depends on — e.g. the salt size `s` for hiding, which a binding
bound does not mention.
-/

namespace VectorCommitment.Security

/-- The security parameter tuple `Θ = (λ, κ, s, ℓ, Q, q)`. -/
structure SecParams where
  /-- target bit-security `λ` -/
  lam : Nat
  /-- digest length in bits, `|Digest| = 2^κ` (binding / extractability axis) -/
  kappa : Nat
  /-- salt-space bit-size, `|R| = 2^s` (hiding axis — distinct from `κ`) -/
  s : Nat
  /-- message length / number of committed leaves -/
  ell : Nat
  /-- number of openings the adversary observes (adaptive budget) -/
  Q : Nat
  /-- the adversary's random-oracle query budget -/
  q : Nat

end VectorCommitment.Security
