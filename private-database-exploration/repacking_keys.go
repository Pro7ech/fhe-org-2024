package pde

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils"
)

type RepackEvaluationKeySet struct {
	Parameters        map[int]*hefloat.Parameters
	RingSwitchingKeys map[int]map[int]*rlwe.EvaluationKey
	RepackKeys        map[int]rlwe.EvaluationKeySet
}

func (rpk RepackEvaluationKeySet) MinLogN() (minLogN int) {
	return utils.GetSortedKeys(rpk.Parameters)[0]
}

func (rpk RepackEvaluationKeySet) MaxLogN() (maxLogN int) {
	return utils.GetSortedKeys(rpk.Parameters)[len(rpk.Parameters)-1]
}

func (rpk *RepackEvaluationKeySet) GenRingSwitchingKeys(p hefloat.Parameters, sk *rlwe.SecretKey, minLogN int, evkParams rlwe.EvaluationKeyParameters) (ski map[int]*rlwe.SecretKey, err error) {

	if minLogN >= p.LogN() {
		return nil, fmt.Errorf("invalid minLogN: cannot be equal or larger than params.LogN()")
	}

	LevelQ, LevelP, _ := rlwe.ResolveEvaluationKeyParameters(*p.GetRLWEParameters(), []rlwe.EvaluationKeyParameters{evkParams})

	Q := p.Q()
	P := p.P()

	Parameters := map[int]*hefloat.Parameters{}
	Parameters[p.LogN()] = &p

	ski = map[int]*rlwe.SecretKey{}
	ski[p.LogN()] = sk

	kgen := map[int]*rlwe.KeyGenerator{}
	kgen[p.LogN()] = rlwe.NewKeyGenerator(p)

	for i := minLogN; i < p.LogN(); i++ {

		var pi hefloat.Parameters
		if pi, err = hefloat.NewParametersFromLiteral(hefloat.ParametersLiteral{
			LogN:            i,
			Q:               Q[:LevelQ+1],
			P:               P[:LevelP+1],
			LogDefaultScale: LogScale,
		}); err != nil {
			return nil, fmt.Errorf("rlwe.NewParametersFromLiteral: %w", err)
		}

		kgen[i] = rlwe.NewKeyGenerator(pi)
		ski[i] = kgen[i].GenSecretKeyNew()
		Parameters[i] = &pi
	}

	// Ring switching evaluation keys
	RingSwitchingKeys := map[int]map[int]*rlwe.EvaluationKey{}

	for i := minLogN; i < p.LogN()+1; i++ {
		RingSwitchingKeys[i] = map[int]*rlwe.EvaluationKey{}
	}

	for i := minLogN; i < p.LogN(); i++ {
		RingSwitchingKeys[i][i+1] = kgen[i+1].GenEvaluationKeyNew(ski[i], ski[i+1], evkParams)
	}

	rpk.Parameters = Parameters
	rpk.RingSwitchingKeys = RingSwitchingKeys

	return ski, nil
}

// GenRepackEvaluationKeys generates the set of params.LogN() [rlwe.EvaluationKey]s necessary to perform the repacking operation.
// See [RingPackingEvaluator.Repack] for additional information.
func (rpk *RepackEvaluationKeySet) GenRepackEvaluationKeys(params rlwe.ParameterProvider, sk *rlwe.SecretKey, evkParams rlwe.EvaluationKeyParameters) {
	p := *params.GetRLWEParameters()

	if rpk.RepackKeys == nil {
		rpk.RepackKeys = map[int]rlwe.EvaluationKeySet{}
	}

	rpk.RepackKeys[p.LogN()] = rlwe.NewMemEvaluationKeySet(nil, rlwe.NewKeyGenerator(p).GenGaloisKeysNew(GaloisElementsForPack(p, p.LogN()), sk, evkParams)...)
}

// GaloisElementsForPack returns the list of Galois elements required to perform the `Pack` operation.
func GaloisElementsForPack(params rlwe.ParameterProvider, logGap int) (galEls []uint64) {

	p := params.GetRLWEParameters()

	// Sanity check
	if logGap > p.LogN() || logGap < 0 {
		panic(fmt.Errorf("cannot GaloisElementsForPack: logGap > logN || logGap < 0"))
	}

	galEls = make([]uint64, 0, logGap)
	for i := 0; i < logGap; i++ {
		galEls = append(galEls, p.GaloisElement(1<<i))
	}

	switch p.RingType() {
	case ring.Standard:
		if logGap == p.LogN() {
			galEls = append(galEls, p.GaloisElementOrderTwoOrthogonalSubgroup())
		}
	default:
		panic("cannot GaloisElementsForPack: invalid ring type")
	}

	return
}
