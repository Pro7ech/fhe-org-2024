# fhe-org-2024
Lattigo presentation for FHE.org 2024 Conference

The constructions used in this code are from a joint work with Malika Izabachène that will be soon accessible on ePrint.

# How to run the code

1. `$ go test -v -run=PDE -timeout=0`

# Private Database Exploration Circuit

A scientist would like to conduct a nation-wide medical study requiring patients with very specific combinations of attributes, but to be funded, the scientist must first conduct a preliminary feasibility study to assess if there are enough patients available in the country's hospitals meeting the study criteria.

This code showcases how Lattigo can be used to perform a privacy-preserving functional database exploration over multiple parties with the following privacy constraints:

- To protect the IP of the study and the privacy of the patients (with respect to hospitals), each hospitals should learn nothing about the selection criteria.
- To protect the privacy of the patients (with respect to the scientist), the scientist should only learn a binary value (if there are enough patients meeting the selection criteria among all the hospitals).

## Setup

This code requires ~22GB of RAM to run with 128-bit secure parameters.

To run with insecure parameters, change the values `LogNPack` and `LogNEval` in the file `parameters.go`.

The test will pring the LogN, LogQP and key distribution of each parameters

### Client

1) Parameters
2) `EvaluationKey`
3) A list of `h'` Private Scoring Functions `[Enc(F[0](x)), Enc(F[1](x)), ..., Enc(F[h'-1](x))]`
4) Private threshold n°1: `Enc(t0)`, `Enc(1/sum(max(F[i]))`
5) Private threshold n°2: `Enc(t1)`

### Server

1) A database of `P` of dimension `#Patients x #Attributs = p x h`

## Circuit

1) The client sends {`Parameters`, `EvaluationKey`, `[Enc(F[0](x)), Enc(F[1](x)), ..., Enc(F[h-1](x))]`, `Enc(t0)`, `Enc(1/sum(max(F[i]))`, `Enc(t1)`}
2) The server evaluate `RLWE[i](sum F[j](p[i][j])X^{0} + *X^{1} + ...) = sum_j X^{p[i][j]} * Enc(F[j](x))`
3) The server repacks the sparse `RLWE` ciphertexts into dense `RLWE` ciphertexts of dimension `2^LogNPack` and merges them into ciphertexts of dimension `2^LogNEval`
4) The server evaluates `Scheme-Switch` which homomorphically encodes the packed `RLWE` ciphertexts into `CKKS` ciphertexts `ct[i]`.
5) For `ct' = 0` and each `RLWE` ciphertext `ct[i]`, the server evaluates `ct' <- ct' + step((ct[i] - Enc(t0)) * Enc(1/sum(max(F[i])))`
6) The server evaluates `ct' <- step((InnerSum(ct') - Enc(t1)) * (1/p) )`
7) The server sends `ct'` back to the client
