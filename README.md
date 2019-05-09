# SIS (short integer solution) problem based zkSNARKs/STARKs friendly accumulator

In short lattice based one-way function may be formulated as the following (links to original article to follow):

- Choose prime (not necessary large) `q(n)`, random matrix `A` of size `m(n) x n`, such that there always exists an integer solution `Ax = z` with `|x| < beta(n)`, where `x` is vector of length `m` and `z` is a vector of length `n`. Such construction may be reduced to a SIS problem that is considered "hard"
- One can reformulate a problem by limiting elements of `x` to be in range `[0, d)` for some `d(n)`, so `beta` can be calculated from `d` and `m`
- Parameters can be tuned to the chosen security level
- Let's take "high" seculity level and start to accululate individual elements `x` as the following:
  - Initial `acc` is zero vector of dimension `n`
  - Add element to the set: `acc += Ax`
  - Witness: `w = A^{-1} *(acc - Ax)` with `|w| < beta_prime`, such that problem of finding witness for element inclusion becomes just another instance of the SIS problem with different security level that would be determined by the number "K" of elements accumulated. Imagine `x` being a bitstring of length `m` so that `|x| < beta`, then `w` would be a vector of length `m` with worst-case elements being `<= K` and `|x| < beta*K`
- Such element is obviously R1CS friendly: we are in a prime field, with calculation of `Ax` taking `n` constraints (consider elements of `x` already constrained to be bits, so we can skip the check `|x| < beta`)
- Witness check would take `n` constraints plus `2 + NUM_BITS` constraints to check `|w| < beta*K` if `beta*K` and squares of elements do not overflow a field modulus

## Disclaimer

Such construction is largely is brainstorm effort and was initially proposed by `@Silur` with this explained prepared by `@shamatar`