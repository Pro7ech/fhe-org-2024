package pde

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils/structs"
)

type Func struct {
	F        func(x float64) (y float64)
	Interval [2]float64
	Max      float64
	Points   int
}

func NewScoringFunction(interval [2]float64, points int, scaling float64) Func {
	return Func{
		F: func(x float64) (y float64) {

			if x > 1.5 {
				return 1 * scaling
			}

			return 0
		},
		Interval: interval,
		Points:   points,
		Max:      9,
	}
}

// TestVector is a set of polynomials encoding a function f(x) = y.
type TestVector struct {
	Value    structs.Vector[rlwe.Ciphertext]
	Interval [2]float64
	Points   int
}

type TestVectors []TestVector

func (tv TestVectors) BinarySize() (size int) {

	for _, v := range tv {
		size += v.Value.BinarySize()
		size += 24
	}

	return
}

func (tv TestVectors) Evaluate(params hefloat.Parameters, values []float64, buffPoly ring.Poly, buffCt *rlwe.Ciphertext) (err error) {
	if len(tv) != len(values) {
		return fmt.Errorf("len(TestVectors) != len(values)")
	}

	N := params.N()
	ringQ := params.RingQ()

	for i := range values {

		t := tv[i]

		// Step size
		interval := 1.0 / float64(t.Points)

		// Maps the value to [0, 1]
		value := normalize(values[i], t.Interval[0], t.Interval[1])

		if value + interval >= 1 {
			return fmt.Errorf("%f not in [%f, %f] or too close to %f", values[i], t.Interval[0], t.Interval[1], t.Interval[1])
		}

		// Computes the index given the value in [0, 1] and the step size
		position := int(math.Round(value / interval))

		hi := int(position) / N       // Index of the ciphertext
		lo := int(position) & (N - 1) // Index of X^{i}

		buffPoly.Zero()
		buffPoly.Coeffs[0][lo] = 1
		ringQ.NTT(buffPoly, buffPoly)

		if i == 0 {
			ringQ.MulCoeffsMontgomery(t.Value[hi].Value[0], buffPoly, buffCt.Value[0])
			ringQ.MulCoeffsMontgomery(t.Value[hi].Value[1], buffPoly, buffCt.Value[1])
		} else {
			ringQ.MulCoeffsMontgomeryThenAdd(t.Value[hi].Value[0], buffPoly, buffCt.Value[0])
			ringQ.MulCoeffsMontgomeryThenAdd(t.Value[hi].Value[1], buffPoly, buffCt.Value[1])
		}
	}

	return
}

// GenTestPolynomials generates a TestPolynomial from a function.
func GenTestPolynomials(params hefloat.Parameters, f Func, ecd *hefloat.Encoder, enc *rlwe.Encryptor) (TestVector, error) {

	points := f.Points
	a, b := f.Interval[0], f.Interval[1]

	u := make([]float64, params.N())

	interval := 1.0 / float64(points)

	pt := hefloat.NewPlaintext(params, 0)
	pt.IsBatched = false

	N := params.N()
	Value := make([]rlwe.Ciphertext, (points+N-1)/N)

	var err error

	ringQ := params.RingQ().AtLevel(0)

	for i := range Value {

		start := i * N
		end := start + N

		if end > points {
			end = points
		}

		u[0] = f.F(normalizeInv(interval*float64(start), a, b))
		for j := 1; j < N; j++ {
			u[N-j] = -f.F(normalizeInv(interval*float64(j+start), a, b))
		}

		if err = ecd.Encode(u, pt); err != nil {
			return TestVector{}, fmt.Errorf("ecd.Encode: %w", err)
		}

		var ct *rlwe.Ciphertext
		if ct, err = enc.EncryptNew(pt); err != nil {
			return TestVector{}, fmt.Errorf("enc.EncryptNew: %w", err)
		}

		ringQ.MForm(ct.Value[0], ct.Value[0])
		ringQ.MForm(ct.Value[1], ct.Value[1])

		Value[i] = *ct
	}

	return TestVector{
		Interval: [2]float64{a, b},
		Points:   points,
		Value:    Value,
	}, nil
}

// [a, b] -> [0, 1]
func normalize(x, a, b float64) (y float64) {
	return ((2*x-b-a)/(b-a) + 1) / 2
}

// [0, 1] -> [a, b]
func normalizeInv(x, a, b float64) (y float64) {
	return ((2*x-1)*(b-a) + b + a) / 2.0
}
