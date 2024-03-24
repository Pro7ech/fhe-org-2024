package pde

import (
	"fmt"
	"math/bits"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/ring"
)

type RepackEvaluator struct {
	*RepackEvaluationKeySet
	Evaluators map[int]*rlwe.Evaluator
	XPow2NTT   map[int][]ring.Poly
}

func NewRepackEvaluator(evk *RepackEvaluationKeySet) *RepackEvaluator {

	Evaluators := map[int]*rlwe.Evaluator{}
	XPow2NTT := map[int][]ring.Poly{}

	minLogN := evk.MinLogN()
	maxLogN := evk.MaxLogN()

	levelQ := evk.Parameters[minLogN].GetRLWEParameters().MaxLevel()

	for i := minLogN; i < maxLogN+1; i++ {
		pi := evk.Parameters[i].GetRLWEParameters()
		Evaluators[i] = rlwe.NewEvaluator(pi, evk.RepackKeys[i])
		XPow2NTT[i] = GenXPow2NTT(pi.RingQ().AtLevel(levelQ), pi.LogN(), false)
	}

	return &RepackEvaluator{
		RepackEvaluationKeySet: evk,
		Evaluators:             Evaluators,
		XPow2NTT:               XPow2NTT,
	}
}

func (eval RepackEvaluator) Pack(cts map[int]*rlwe.Ciphertext) (ct *rlwe.Ciphertext, err error) {
	return eval.Evaluators[LogNPack].Pack(cts, LogNPack, true)
}

// Merge merges two ciphertexts of degree N/2 into a ciphertext of degre N:
// ctN[X] = ctEvenNHalf[Y] + X * ctOddNHalf[Y] where Y = X^2.
func (eval RepackEvaluator) Merge(ctEvenNHalf, ctOddNHalf, ctN *rlwe.Ciphertext) (err error) {

	if eval.MinLogN() == eval.MaxLogN() {
		return fmt.Errorf("method is not supported when eval.MinLogN() == eval.MaxLogN()")
	}

	if ctEvenNHalf == nil {
		return fmt.Errorf("ctEvenNHalf cannot be nil")
	}

	if bits.Len64(uint64(len(ctEvenNHalf.Value[0].Coeffs[0])-1)) >= eval.MaxLogN() {
		return fmt.Errorf("ctEvenNHalf.LogN() must be smaller than eval.MaxLogN()")
	}

	if bits.Len64(uint64(len(ctN.Value[0].Coeffs[0])-1)) != bits.Len64(uint64(len(ctEvenNHalf.Value[0].Coeffs[0])-1))+1 {
		return fmt.Errorf("ctN.LogN() must be equal to ctEvenNHalf.LogN()+1")
	}

	if ctOddNHalf != nil {
		if bits.Len64(uint64(len(ctEvenNHalf.Value[0].Coeffs[0])-1)) != bits.Len64(uint64(len(ctOddNHalf.Value[0].Coeffs[0])-1)) {
			return fmt.Errorf("ctEvenNHalf.LogN() and ctOddNHalf.LogN() must be equal")
		}
	}

	LogN := bits.Len64(uint64(len(ctN.Value[0].Coeffs[0]) - 1))

	evalN := eval.Evaluators[LogN]
	evkNHalfToN := eval.RingSwitchingKeys[LogN-1][LogN]
	r := eval.Parameters[LogN].GetRLWEParameters().RingQ().AtLevel(ctN.Level())

	ctTmp := rlwe.NewCiphertext(eval.Parameters[LogN], 1, ctN.Level())

	if ctEvenNHalf != nil {

		*ctN.MetaData = *ctEvenNHalf.MetaData
		rlwe.SwitchCiphertextRingDegreeNTT(ctEvenNHalf.El(), r, ctN.El())

		if ctOddNHalf != nil {
			rlwe.SwitchCiphertextRingDegreeNTT(ctOddNHalf.El(), r, ctTmp.El())
			r.MulCoeffsMontgomeryThenAdd(ctTmp.Value[0], eval.XPow2NTT[LogN][0], ctN.Value[0])
			r.MulCoeffsMontgomeryThenAdd(ctTmp.Value[1], eval.XPow2NTT[LogN][0], ctN.Value[1])
		}
	}

	// SkNHalf -> SkN
	if err = evalN.ApplyEvaluationKey(ctN, evkNHalfToN, ctN); err != nil {
		return fmt.Errorf("evalN.ApplyEvaluationKey(ctN, evkNToNHalf, ctN): %w", err)
	}

	ctN.LogDimensions.Cols++
	return
}

// MergeNew merges two ciphertexts of degree N/2 into a ciphertext of degre N:
// ctN[X] = ctEvenNHalf[Y] + X * ctOddNHalf[Y] where Y = X^2.
func (eval RepackEvaluator) MergeNew(ctEvenNHalf, ctOddNHalf *rlwe.Ciphertext) (ctN *rlwe.Ciphertext, err error) {

	if eval.MinLogN() == eval.MaxLogN() {
		return nil, fmt.Errorf("method is not supported when eval.MinLogN() == eval.MaxLogN()")
	}

	if ctEvenNHalf == nil {
		return nil, fmt.Errorf("ctEvenNHalf cannot be nil")
	}

	LogN := bits.Len64(uint64(len(ctEvenNHalf.Value[0].Coeffs[0]) - 1))

	if LogN >= eval.MaxLogN() {
		return nil, fmt.Errorf("ctEvenNHalf.LogN() must be smaller than eval.MaxLogN()")
	}

	ctN = rlwe.NewCiphertext(eval.Parameters[LogN+1], 1, ctEvenNHalf.Level())
	return ctN, eval.Merge(ctEvenNHalf, ctOddNHalf, ctN)
}
