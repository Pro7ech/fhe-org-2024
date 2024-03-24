package largef

import (
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
)

// Server is a struct storing the necessary elements
// for the server-side evaluation of the circuit.
type Server struct {
	T uint64
	heint.Parameters
	*heint.Evaluator
	*heint.Encoder
}

// NewServer instantiates a new server.
func NewServer(params heint.Parameters, T uint64) *Server {
	return &Server{
		T:          T,
		Parameters: params,
		Evaluator:  heint.NewEvaluator(params, nil),
		Encoder:    heint.NewEncoder(params),
	}
}

// Evaluate evaluates the test polynomials on a set of encrypted points.
func (s Server) Evaluate(ctXi []Points, ptU []TestPoly, evk rlwe.EvaluationKeySet) (final *rlwe.Ciphertext) {

	params := s.Parameters
	eval := s.Evaluator.WithKey(evk)

	var err error

	// Evaluate u x Enc(X^i) -> Enc(f(i)) by summation over the split domains
	res := make(map[int]*rlwe.Ciphertext)
	for i := range ctXi[0] {
		res[i] = heint.NewCiphertext(params, 1, params.MaxLevel())
		res[i].IsBatched = false
	}

	ringQ := params.RingQ()

	for k := range ctXi {

		ctXik := ctXi[k]
		ptUk := ptU[k]

		for i := range ctXik {

			r := res[i]

			// Supports up to 2^{64-LogQ} sequential additions without modular reduction
			// poly-mul in the NTT and Montgomery domain
			for j := range ctXik[i] {
				if k == 0 && j == 0 {
					ringQ.MulCoeffsMontgomeryLazy(ctXik[i][j].Value[0], ptUk[j], r.Value[0])
					ringQ.MulCoeffsMontgomeryLazy(ctXik[i][j].Value[1], ptUk[j], r.Value[1])
				} else {
					ringQ.MulCoeffsMontgomeryLazyThenAddLazy(ctXik[i][j].Value[0], ptUk[j], r.Value[0])
					ringQ.MulCoeffsMontgomeryLazyThenAddLazy(ctXik[i][j].Value[1], ptUk[j], r.Value[1])
				}
			}

			// Modular reduction of the polynomials coefficient
			ringQ.Reduce(r.Value[0], r.Value[0])
			ringQ.Reduce(r.Value[1], r.Value[1])
		}
	}

	if len(res) > 1 {
		// Pack all Enc(f(i)) into a single RLWE ciphertext
		if final, err = eval.Pack(res, params.LogN(), false); err != nil {
			panic(err)
		}
	} else {
		final = res[0]
	}

	return
}
