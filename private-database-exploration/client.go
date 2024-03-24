package pde

import (
	"fmt"
	"math/bits"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/utils"
)

type Client struct {
	Parameters map[int]*hefloat.Parameters
	Ski        map[int]*rlwe.SecretKey
}

func NewClient() (c Client) {
	return Client{}
}

type Request struct {
	*EvaluationKeys
	*TestVectors
	PrivateThreshold0 *PrivateThreshold
	PrivateThreshold1 *PrivateThreshold
}

type PrivateThreshold struct {
	Threshold     *rlwe.Ciphertext
	Normalization *rlwe.Ciphertext
}

type EvaluationKeys struct {
	RepackEvaluationKeySet
	bootstrapping.EvaluationKeys
}

func (c Client) Decrypt(score *rlwe.Ciphertext) (v []complex128, err error) {

	LogN := bits.Len64(uint64(len(score.Value[0].Coeffs[0]) - 1))

	params := c.Parameters[LogN]
	sk := c.Ski[LogN]
	dec := hefloat.NewDecryptor(*params, sk)
	ecd := hefloat.NewEncoder(*params)
	v = make([]complex128, score.Slots())
	return v, ecd.Decode(dec.DecryptNew(score), v)
}

func (c Client) GenEncryptedFunction(funcs []Func) (encFuncs TestVectors, err error) {

	params := *c.Parameters[LogNPack]
	enc := rlwe.NewEncryptor(params, c.Ski[LogNPack])
	ecd := hefloat.NewEncoder(params)

	encFuncs = make([]TestVector, len(funcs))

	for i := range funcs {
		if encFuncs[i], err = GenTestPolynomials(params, funcs[i], ecd, enc); err != nil {
			return nil, fmt.Errorf("GenTestPolynomials: %w", err)
		}
	}

	fmt.Println("EncFunc Size MB: ", float64(encFuncs.BinarySize())/1048576)

	return
}

func (c Client) GenPrivateThreshold(threshold float64, f []Func) (p PrivateThreshold, err error) {

	params := *c.Parameters[LogNEval]

	enc := rlwe.NewEncryptor(params, c.Ski[LogNEval])
	ecd := hefloat.NewEncoder(params)

	pt := hefloat.NewPlaintext(params, params.MaxLevel())
	pt.IsBatched = false

	if err = ecd.Encode([]float64{threshold}, pt); err != nil {
		return PrivateThreshold{}, fmt.Errorf("ecd.Encode: %w", err)
	}

	tEnc, err := enc.EncryptNew(pt)

	if err != nil {
		return PrivateThreshold{}, fmt.Errorf("enc.EncryptNew: %w", err)
	}

	tEnc.IsBatched = true

	var tNorm *rlwe.Ciphertext

	size := tEnc.BinarySize()

	var max float64
	for i := range f {
		max += f[i].Max
	}

	if max != 0 {

		pt.Scale = rlwe.NewScale(params.Q()[params.MaxLevel()])

		if err = ecd.Encode([]float64{1 / max}, pt); err != nil {
			return PrivateThreshold{}, fmt.Errorf("ecd.Encode: %w", err)
		}

		if tNorm, err = enc.EncryptNew(pt); err != nil {
			return PrivateThreshold{}, fmt.Errorf("enc.EncryptNew: %w", err)
		}

		tNorm.IsBatched = true

		size += tNorm.BinarySize()
	}

	fmt.Println("Enc Treshold Size MB:", float64(size)/1048576)

	return PrivateThreshold{
		Threshold:     tEnc,
		Normalization: tNorm,
	}, nil

}

func (c *Client) Init() (evk EvaluationKeys, err error) {

	paramsEval, err := hefloat.NewParametersFromLiteral(ParametersLiteralLogN16)

	if err != nil {
		return evk, fmt.Errorf("hefloat.NewParametersFromLiteral: %w", err)
	}

	kgen := rlwe.NewKeyGenerator(paramsEval)
	Sk16 := kgen.GenSecretKeyNew()

	evkRPK := RepackEvaluationKeySet{}

	evkParams := rlwe.EvaluationKeyParameters{
		LevelQ:               utils.Pointy(0),
		LevelP:               utils.Pointy(0),
		BaseTwoDecomposition: utils.Pointy(30),
	}

	if c.Ski, err = evkRPK.GenRingSwitchingKeys(paramsEval, Sk16, LogNPack, evkParams); err != nil {
		return evk, fmt.Errorf("evkRPK.GenRingSwitchingKeys: %w", err)
	}

	evkRPK.GenRepackEvaluationKeys(evkRPK.Parameters[LogNPack], c.Ski[LogNPack], evkParams)

	c.Parameters = evkRPK.Parameters

	var btpParams bootstrapping.Parameters
	if btpParams, err = bootstrapping.NewParametersFromLiteral(paramsEval, BootstrappingParametersLiteral); err != nil {
		return evk, fmt.Errorf("bootstrapping.NewParametersFromLiteral: %w", err)
	}

	for i := LogNPack; i < LogNEval; i++ {
		p := c.Parameters[i]
		fmt.Printf("Params Pack LogN=%d LogQP=%10.5f Xs=%v Xe=%v\n", i, p.LogQP(), p.Xs(), p.Xe())
	}
	fmt.Printf("Params Eval LogN=%d LogQP=%10.5f Xs=%v Xe=%v\n", LogNEval, c.Parameters[LogNEval].LogQP(), c.Parameters[LogNEval].Xs(), c.Parameters[LogNEval].Xe())
	fmt.Printf("Params Boot LogN=%d LogQP=%10.5f Xs=%v Xe=%v\n", LogNEval, btpParams.BootstrappingParameters.LogQP(), btpParams.BootstrappingParameters.Xs(), btpParams.BootstrappingParameters.Xe())

	var evkBoot *bootstrapping.EvaluationKeys
	if evkBoot, _, err = btpParams.GenEvaluationKeys(Sk16); err != nil {
		return evk, fmt.Errorf("btpParams.GenEvaluationKeys: %w", err)
	}

	// Prints some infos

	var RingSwitchingKeys int
	for i := range evkRPK.RingSwitchingKeys {
		for _, j := range evkRPK.RingSwitchingKeys[i] {
			RingSwitchingKeys += j.BinarySize()
		}
	}

	var RepackKeys int
	for i := range evkRPK.RepackKeys {
		for _, j := range evkRPK.RepackKeys[i].GetGaloisKeysList() {
			d, _ := evkRPK.RepackKeys[i].GetGaloisKey(j)
			RepackKeys += d.BinarySize()
		}
	}

	fmt.Println("RingSwitchingKeys MB:", float64(RingSwitchingKeys)/1048576)
	fmt.Println("RepackKeys MB:", float64(RepackKeys)/1048576)
	fmt.Println("BootstrappingKeys MB:", float64(evkBoot.BinarySize())/1048576)

	return EvaluationKeys{
		RepackEvaluationKeySet: evkRPK,
		EvaluationKeys:         *evkBoot,
	}, nil
}
