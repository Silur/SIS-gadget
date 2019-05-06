## Accumulation procedure

- Generate parameters `q, n, m, A`
- Get binary string `x` of length `m`
- perform affine transformation `Ax = z` and get a vector `z` of length `m` of values modulo `q`
- use accumulator `acc` that is initially is empty vector of length `n` of values modulo `q`
- on each step `acc = acc + z` 

Questions:
- general correctness
- should one check that `|x| < beta`?
- will properties be affected if most of the `x` is zeroes (especially if first `k` elements are always known to be zero)?
- Is there a limit for a number of values being accumulated?

## Witness 

- perform affine transformation `Ax = z` and get a vector `z` of length `m` of values modulo `q`
- use accumulator `acc` that is initially is empty vector of length `n` of values modulo `q`
- on each step `acc = acc + z` 
- witness is `wit = A(-x) + acc`
- verification `wit + z = acc + A(-x) + Ax = acc`

Questions:
- general correctness
