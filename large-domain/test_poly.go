package largef

import (
	"github.com/tuneinsight/lattigo/v5/ring"
)

// TestPoly is a set of polynomials encoding a function f(x) = y mod T.
type TestPoly []ring.Poly

// GenTestPolynomials generates a TestPolynomial from a function.
func (s Server) GenTestPolynomials(f func(x uint64) (y uint64), T uint64) (ptU TestPoly) {

	params := s.Parameters
	ecd := s.Encoder

	N := params.N()
	PlaintextModulus := params.PlaintextModulus()
	ringQ := params.RingQ()

	ptU = make([]ring.Poly, (int(T)+N-1)/N)

	// Test polynomial
	u := params.RingT().NewPoly()
	coeffs := u.Coeffs[0]

	for i := range ptU {

		start := i * N
		end := start + N

		if end > int(T) {
			end = int(T)
		}

		// U(X) = f(i) - f(N-1)*X - f(N-2) * X^2 - ... - f(2) * X^{N-1}
		coeffs[0] = f(uint64(start))
		for j, k := start+1, 0; j < end; j, k = j+1, k+1 {
			coeffs[N-k-1] = PlaintextModulus - f(uint64(j))
		}

		ptU[i] = ringQ.NewPoly()

		// False = not scale by T^{-1} mod Q
		ecd.RingT2Q(ptU[i].Level(), false, u, ptU[i])

		// Montgomery domain
		params.RingQ().MForm(ptU[i], ptU[i])

		// NTT domain
		params.RingQ().NTT(ptU[i], ptU[i])
	}

	return
}
