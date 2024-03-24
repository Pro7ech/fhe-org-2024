package largef

import (
	"github.com/tuneinsight/lattigo/v5/he/heint"
)

const (
	// LogN is the ring degree N of R_Q[X]/(X^{N} + 1).
	LogN = 11

	// LogQ is the log2(Q) of the modulus of R_Q[X]/(X^{N} + 1).
	LogQ = 54

	// PlaintextModulus is the plaintext domain.
	PlaintextModulus uint64 = 65537

	// BaseTwoDecomposition is the power of two decomposition
	// of the evaluation keys.
	BaseTwoDecomposition = 14
)

// GetParameters instantiates a new heint.Parameters.
func GetParameters() (params heint.Parameters, err error) {
	// N=2048 & Log(Q) = 54
	// Default error distribution: discrete Gaussian with sigma=3.2 bounded by ceil(6*sigma)
	// Default secret distribution: uniform ternary
	// Security: 128-bit
	return heint.NewParametersFromLiteral(heint.ParametersLiteral{
		LogN:             LogN,             //Log2 of the ring degree
		LogQ:             []int{LogQ},      // Bit-size of the primes moduli
		PlaintextModulus: PlaintextModulus, // Plaintext modulus, should be >= Function Domain
	})
}
