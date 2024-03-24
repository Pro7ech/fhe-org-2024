package pde

import (
	"fmt"
	"time"

	"github.com/tuneinsight/lattigo/v5/ring"
)

func RunTimed(msg string, f func() (err error)) (err error) {
	fmt.Printf("%s: ", msg)
	now := time.Now()
	if err = f(); err != nil {
		return
	}
	fmt.Printf("%s\n", time.Since(now))
	return
}

// MinimaxCompositePolynomialForSignThreshold0 is an example of composite minimax polynomial
// for the sign function that is able to distinguish between value with a delta of up to
// 2^{-alpha=8}, tolerates a scheme error of 2^{-12} and outputs a binary value (-1, or 1)
// of up to 14.0 bits of precision.
//
// It was computed with hefloat.GenMinimaxCompositePolynomialForSign(256, 8, 12, []int{15, 15, 15}).
var MinimaxCompositePolynomialForSignThreshold0 = [][]string{
	{"0", "0.667972070856", "0", "-0.223989523020", "0", "0.136121229346", "0", "-0.099160550898", "0", "0.079224867308", "0", "-0.067250088206", "0", "0.059852569462", "0", "-0.503955481350"},
	{"0", "0.955669291788", "0", "-0.317870998995", "0", "0.189953989728", "0", "-0.134924463410", "0", "0.104260767625", "0", "-0.084798113265", "0", "0.071534728674", "0", "-0.282024623439"},
	{"0", "1.254717353059", "0", "-0.371638622338", "0", "0.175181567419", "0", "-0.085946606966", "0", "0.039326533561", "0", "-0.015616729371", "0", "0.004903749402", "0", "-0.000987938705"},
}

// MinimaxCompositePolynomialForSignThreshold1 is an example of composite minimax polynomial
// for the sign function that is able to distinguish between value with a delta of up to
// 2^{-alpha=16}, tolerates a scheme error of 2^{-20} and outputs a binary value (-1, or 1)
// of up to 9.4 bits of precision.
//
// It was computed with hefloat.GenMinimaxCompositePolynomialForSign(256, 16, 20, []int{15, 15, 15, 15, 15}).
var MinimaxCompositePolynomialForSignThreshold1 = [][]string{
	{"0", "0.637268817143423", "0", "-0.213843858840010", "0", "0.130068019801244", "0", "-0.094901182442864", "0", "0.076054612814770", "0", "-0.064781641895431", "0", "0.057798688832330", "0", "-0.527470371234989"},
	{"0", "0.638695683522550", "0", "-0.214316818308012", "0", "0.130348567125999", "0", "-0.095098055756955", "0", "0.076204005701363", "0", "-0.064899954787194", "0", "0.057894713727750", "0", "-0.526392177258839"},
	{"0", "0.656606626265620", "0", "-0.220250173467088", "0", "0.133863750202729", "0", "-0.097560013608431", "0", "0.078066936262030", "0", "-0.066369507148038", "0", "0.059080919875980", "0", "-0.512846436037889"},
	{"0", "0.855861960962205", "0", "-0.285691381624270", "0", "0.171944105417797", "0", "-0.123469618435643", "0", "0.096847091991917", "0", "-0.080284982264950", "0", "0.069319087833638", "0", "-0.360370937154585"},
	{"0", "1.261257106681966", "0", "-0.389575144395675", "0", "0.200091626583035", "0", "-0.112254644903536", "0", "0.062146884728848", "0", "-0.032085565037577", "0", "0.014550986557278", "0", "-0.005542572455981"},
}

// GenXPow2NTT generates X^({-1 if div else 1} * {2^{0 <= i < LogN}}) in NTT.
func GenXPow2NTT(r *ring.Ring, logN int, div bool) (xPow []ring.Poly) {

	// Compute X^{-n} from 0 to LogN
	xPow = make([]ring.Poly, logN)

	moduli := r.ModuliChain()[:r.Level()+1]
	BRC := r.BRedConstants()

	var idx int
	for i := 0; i < logN; i++ {

		idx = 1 << i

		if div {
			idx = r.N() - idx
		}

		xPow[i] = r.NewPoly()

		if i == 0 {

			for j := range moduli {
				xPow[i].Coeffs[j][idx] = ring.MForm(1, moduli[j], BRC[j])
			}

			r.NTT(xPow[i], xPow[i])

		} else {
			r.MulCoeffsMontgomery(xPow[i-1], xPow[i-1], xPow[i]) // X^{n} = X^{1} * X^{n-1}
		}
	}

	if div {
		r.Neg(xPow[0], xPow[0])
	}

	return
}
