package largef

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/utils/sampling"
)

const (
	// T is the input function domain.
	// Must be smaller or equal to params.PlaintextModulus().
	// Current plaintext modulus is hard-coded to 65537,
	// but can be changed to something greater/smaller. Evaluation
	// keys gadget decomposition might have to be updated if a larger
	// plaintext modulus is used to reduce the noise bound.
	// Plaintext modulus needs to be congruent to 1 mod 2N.
	T uint64 = 1 << 15

	// NbPoints is the number of points to evaluate per call of the protocol.
	// Optimal number is N, which in our case the number of points to be the ring degree.
	NbPoints = 2048

	// Some constants for the functions, that can be manually changed/removed.
	b     uint64 = 257
	h     uint64 = 257
	max   uint64 = T
	alpha uint64 = max/h + 1
)

// Set of function to combine, functions can be
// added/removed freely.
var F = []func(x uint64) (y uint64){
	func(x uint64) (y uint64) { return x / b * alpha },
	func(x uint64) (y uint64) { return x / h },
}

func TestLargeF(t *testing.T) {

	params, err := GetParameters()
	require.NoError(t, err)

	if NbPoints > params.N() {
		t.Fatal(fmt.Sprintf("NbPoints = %d cannot be greater than params.N() = %d", NbPoints, params.N()))
	}

	client := NewClient(params, T)
	server := NewServer(params, T)

	maxBigint := new(big.Int).SetUint64(max)

	// Creates `NbPoints` random points for each function.
	points := make([][]uint64, len(F))
	for i := range points {
		v := make([]uint64, NbPoints)
		for j := range v {
			v[j] = sampling.RandInt(maxBigint).Uint64()
		}
		points[i] = v
	}

	// Generate the Test Polynomials for split domain [Z_N U Z_N U ... U Z_N >= Z_T]-> [Z_T] (i.e. k=ceil(T/N))
	// for each function Fi
	ptF := make([]TestPoly, len(F))
	runTimed(fmt.Sprintf("Gen %d Test Polynomials F(i) for 0<= i < %d", len(F), T), func() {
		for i := range F {
			ptF[i] = server.GenTestPolynomials(F[i], T)
		}
	})

	// Client encryption of all points.
	ctPoints := make([]Points, len(F))
	runTimed(fmt.Sprintf("Client Encryption X^{xi, yi, ...} for 0 <= i < %d", NbPoints), func() {
		for i := range points {
			ctPoints[i] = client.Encrypt(points[i])
		}
	})

	fmt.Printf("Query Size: tot: %d MB - point: %d KB\n", (len(ctPoints)*NbPoints*len(ctPoints[0][0])*ctPoints[0][0][0].BinarySize())>>20, len(ctPoints)*len(ctPoints[0][0])*ctPoints[0][0][0].BinarySize()>>10)
	fmt.Printf("Evaluation Keys Size: %d KB\n", client.MemEvaluationKeySet.BinarySize()>>10)

	// Server evaluation of G(xi, yi, ...)
	var finalG *rlwe.Ciphertext
	fmt.Println()
	runTimed(fmt.Sprintf("Server Evaluation: G(xi, yi, ...) = Repack(F1 + F2 + ...) for 0 <= i < %d", NbPoints), func() {
		finalG = server.Evaluate(ctPoints, ptF, client.MemEvaluationKeySet)
	})

	// The size of the response can be improved by trunckating the lower bits by
	// switching to a smaller modulus. Typically a size of 4 bytes per coefficient
	// can be achieve, reducing it to 16KB instead of 32KB (8 bytes per coefficient).
	fmt.Printf("Response Size: %d KB\n", finalG.BinarySize()>>10)

	// Client decryption
	var vG []uint64
	fmt.Println()
	runTimed(fmt.Sprintf("Client Decryption"), func() {
		vG = client.Decrypt(finalG)[:NbPoints]
	})

	// Print some stats about the noise
	// Standard deviation, minimum, maximum and
	// maximum allowed to enable correct decryption.
	client.PrintNoise(finalG, vG)

	// Check correctness for all points and prints the first 16 points
	fmt.Println()
	fmt.Println("First 16 points:")
	for i := 0; i < NbPoints; i++ {

		var want uint64
		for j := range F {
			want += F[j](points[j][i])
		}

		if want != vG[i] {
			var str string
			str += fmt.Sprintf("wrong result: G(")
			for j := range points {
				str += fmt.Sprintf("%5d,", points[j][i])
			}
			str += fmt.Sprintf(")=%d but have %d", want, vG[i])
			panic(str)
		}

		if i < 16 {
			fmt.Printf("G(")
			for j := range points {
				fmt.Printf("%5d,", points[j][i])
			}
			fmt.Printf(") = %5d | ok!\n", vG[i])
		}
	}
}

func runTimed(op string, f func()) {
	now := time.Now()
	fmt.Printf("%s: ", op)
	f()
	fmt.Printf("%s\n", time.Since(now))
}
