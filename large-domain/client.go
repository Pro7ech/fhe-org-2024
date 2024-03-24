package largef

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/heint"
	"github.com/tuneinsight/lattigo/v5/utils"
)

// Points is a struct storing a set of encrypts points.
type Points [][]*rlwe.Ciphertext

// Client is a struct storing the necessary elements
// to encode, encrypt and decrypt points.
type Client struct {
	T uint64
	heint.Parameters
	*heint.Encoder
	*rlwe.Encryptor
	*rlwe.Decryptor
	*rlwe.MemEvaluationKeySet
}

// NewClient instantiates a new client.
func NewClient(params heint.Parameters, T uint64) *Client {
	// Instantiates an rlwe.KeyGenerator
	kgen := heint.NewKeyGenerator(params)

	// Generates the client secret key
	sk := kgen.GenSecretKeyNew()

	// Instantiates an rlwe.Encryptor, rlwe.Decryptor and heint.Encoder
	enc := heint.NewEncryptor(params, sk)
	dec := heint.NewDecryptor(params, sk)
	ecd := heint.NewEncoder(params)

	// Galois elements needed for the repacking
	galEls := params.GaloisElementsForPack(params.LogN())

	// Since we do not use a modulus P, we need to specify a base-2 decomposition
	// parameters for the evaluation keys to control the noise
	evkParams := rlwe.EvaluationKeyParameters{BaseTwoDecomposition: utils.Pointy(BaseTwoDecomposition)}

	// Generates a list of Galois keys from the provided Galois elements
	// Galois keys is public-material that can be shared.
	gks := kgen.GenGaloisKeysNew(galEls, sk, evkParams)

	// Struct holding the keys compliant to the rlwe.EvaluationKeySet interface
	evk := rlwe.NewMemEvaluationKeySet(nil, gks...)

	return &Client{
		T:                   T,
		Parameters:          params,
		Encoder:             ecd,
		Encryptor:           enc,
		Decryptor:           dec,
		MemEvaluationKeySet: evk,
	}
}

// Encrypt encrypts a list of points.
func (c Client) Encrypt(points []uint64) (ctXi Points) {

	params := c.Parameters
	ecd := c.Encoder
	enc := c.Encryptor
	T := c.T

	// Generate Enc(X^i) with split domain [Z_N U Z_N U ... U Z_N >= Z_T]
	ctXi = make([][]*rlwe.Ciphertext, len(points))

	// Buffer
	ptXi := heint.NewPlaintext(params, params.MaxLevel())

	// Encrypt each point
	m := make([]uint64, params.N())
	for i := range ctXi {
		ctXi[i] = encryptXi(params, points[i], T, m, ptXi, ecd, enc)
	}

	return
}

func encryptXi(params heint.Parameters, i, T uint64, m []uint64, pt *rlwe.Plaintext, ecd *heint.Encoder, enc *rlwe.Encryptor) (ctXi []*rlwe.Ciphertext) {

	N := params.N()

	hi := int(i) / N // Index of the ciphertext
	lo := int(i) % N // Index of X^{i}

	m[lo] = 1
	pt.IsBatched = false // i.e. tags that the plaintext has no special encoding
	if err := ecd.Encode(m, pt); err != nil {
		panic(err)
	}
	m[lo] = 0

	ctXi = make([]*rlwe.Ciphertext, (int(T)+N-1)/N)
	for i := range ctXi {
		ctXi[i] = enc.EncryptZeroNew(params.MaxLevel())
	}

	// Adds Xi to the relevant ciphertext
	params.RingQ().Add(ctXi[hi].Value[0], pt.Value, ctXi[hi].Value[0])

	return
}

// Decrypt decrypts and decodes the result.
func (c Client) Decrypt(ct *rlwe.Ciphertext) (v []uint64) {

	params := c.Parameters
	ecd := c.Encoder
	dec := c.Decryptor

	// Decrypts and decodes the result on v
	v = make([]uint64, params.N())
	if err := ecd.Decode(dec.DecryptNew(ct), v); err != nil {
		panic(err)
	}

	return
}

// PrintNoise prints the standard deviation, minimum and maximum residual noise,
// as well as the maximum allowed to enable correct decryption.
func (c Client) PrintNoise(ct *rlwe.Ciphertext, want []uint64) {

	params := c.Parameters
	ecd := c.Encoder
	dec := c.Decryptor

	pt := heint.NewPlaintext(params, ct.Level())
	*pt.MetaData = *ct.MetaData

	if err := ecd.Encode(want, pt); err != nil {
		panic(err)
	}

	params.RingQ().AtLevel(ct.Level()).Sub(ct.Value[0], pt.Value, ct.Value[0])

	vartmp, min, max := rlwe.Norm(ct, dec)

	fmt.Println()
	fmt.Printf("Log2(Noise): std=%f | min=%f | max=%f (max %f for correct decryption)\n", vartmp, min, max, math.Log2(float64(params.Q()[0])/float64(2*params.PlaintextModulus())))
}
