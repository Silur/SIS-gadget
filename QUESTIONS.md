## Accumulation procedure

- Generate parameters `q, n, m, A`
- Get binary string `x` of length `m`
- perform affine transformation `Ax = z` and get a vector `z` of length `m` of values modulo `q`
- use accumulator `acc` that is initially is empty vector of length `n` of values modulo `q`
- on each step `acc = acc + z` 

Questions:
- **general correctness**
- **should one check that `|x| < beta`?**
  Yes, this is part of the SIS -> SIVP transition proof and always the case to form an LLL-resistant structure
- **will properties be affected if most of the `x` is zeroes (especially if first `k` elements are always known to be zero)?**
  No, even if the underlying matrix has non-uniform (but gaussian) distribution. It's actually easier to prove correctness with the later.
- **Is there a limit for a number of values being accumulated?**
  To my knowledge there isn't.
  
## Witness 

- perform affine transformation `Ax = z` and get a vector `z` of length `m` of values modulo `q`
- use accumulator `acc` that is initially is empty vector of length `n` of values modulo `q`
- on each step `acc = acc + z` 
- witness is `wit = A(-x) + acc`
- verification `wit + z = acc + A(-x) + Ax = acc`

Questions:
- **general correctness**
  Correctness can be proven for either the uniform distribution with `q^n` hypercubes or a much easier method shown by https://cims.nyu.edu/~regev/papers/average.pdf using "non-well shaped" regions of the original Lattice.
