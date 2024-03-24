package pde

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
)

func TestFunction(t *testing.T) {

	params, err := hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
		LogN:            12,
		LogQ:            []int{60},
		LogP:            []int{60},
		LogDefaultScale: 40,
	})

	kgen := hefloat.NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()

	ecd := hefloat.NewEncoder(params)
	enc := hefloat.NewEncryptor(params, sk)
	dec := hefloat.NewDecryptor(params, sk)

	a := -20.0
	b := 20.0

	points := 4 * params.N()

	step := 2 / float64(points)

	f := Func{
		F: func(x float64) (y float64) {
			return x / (math.Exp(-x) + 1)
		},
		Interval: [2]float64{a, b},
		Points:   points,
	}

	poly, err := GenTestPolynomials(params, f, ecd, enc)
	require.NoError(t, err)

	polys := TestVectors([]TestVector{poly, poly})

	buffCt := hefloat.NewCiphertext(params, 1, 0)
	buffCt.IsBatched = false

	buffPoly := params.RingQ().NewPoly()

	for i := 0; i < points; i++ {
		x := a + float64(i)*step
		v := []float64{0}
		polys.Evaluate(params, []float64{x, x}, buffPoly, buffCt)
		require.NoError(t, ecd.Decode(dec.DecryptNew(buffCt), v))
		require.InDelta(t, 0, math.Abs(v[0]-2*f.F(x)), 1e-8)
	}
}

func runTimed(f func()) {
	now := time.Now()
	f()
	fmt.Println(time.Since(now))
}
