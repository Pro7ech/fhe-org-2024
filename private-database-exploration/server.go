package pde

import (
	"fmt"
	"math/bits"
	"runtime"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
	"github.com/tuneinsight/lattigo/v5/utils"
)

type Server struct {
	SkDebug                map[int]*rlwe.SecretKey
	SecretKeyBootstrapping bool
	DecEval                *rlwe.Decryptor
	DecPack                *rlwe.Decryptor
	EcdEval                *hefloat.Encoder
	EcdPack                *hefloat.Encoder
	EvalRepack             *RepackEvaluator
	Bootstrapper
	ParamsPack hefloat.Parameters
	ParamsEval hefloat.Parameters
}

func NewServer() Server {
	return Server{}
}

func (s Server) ProcessRequest(r Request, db *Database, btp Bootstrapper) (score *rlwe.Ciphertext, err error) {

	s.Bootstrapper = btp

	s.ParamsPack = hefloat.Parameters{Parameters: ckks.Parameters{Parameters: *r.Parameters[LogNPack].GetRLWEParameters()}}
	s.ParamsEval = hefloat.Parameters{Parameters: ckks.Parameters{Parameters: *r.Parameters[LogNEval].GetRLWEParameters()}}

	paramsPack := s.ParamsPack
	paramsEval := s.ParamsEval

	s.EvalRepack = NewRepackEvaluator(&r.EvaluationKeys.RepackEvaluationKeySet)

	if sk, ok := s.SkDebug[LogNEval]; ok {
		s.DecEval = hefloat.NewDecryptor(paramsEval, sk)
		s.EcdEval = hefloat.NewEncoder(paramsEval)
	}

	if sk, ok := s.SkDebug[LogNPack]; ok {
		s.DecPack = hefloat.NewDecryptor(paramsPack, sk)
		s.EcdPack = hefloat.NewEncoder(paramsPack)
	}

	rows, cols := db.Dims()

	m := db.RawMatrix().Data

	for i := 0; i < 4; i++ {
		for j := 0; j < cols; j++ {
			fmt.Printf("%7.4f ", m[i*cols+j])
		}
		fmt.Printf("...\n")
	}
	fmt.Println()

	// ENCRYPTED LOOKUP-TABLES
	// RING-PACKING
	var res []*rlwe.Ciphertext
	if res, err = s.EncryptedLookupTablesAndRingPacking(db, r.TestVectors); err != nil {
		return nil, fmt.Errorf("s.EncryptedLookupTablesAndRingPacking: %w", err)
	}

	r.TestVectors = nil
	db = nil
	runtime.GC()

	for i := range res {
		s.PrintDebug(fmt.Sprintf("Repack f(xi) [%d]", i), res[i], float64(Scaling))
	}

	// RING MERGING
	var resMerged []*rlwe.Ciphertext
	if resMerged, err = s.RingMerging(res); err != nil {
		return nil, fmt.Errorf("s.RingMerging: %w", err)
	}

	for i := range resMerged {
		s.PrintDebug(fmt.Sprintf("Merged f(xi) [%d]", i), resMerged[i], float64(Scaling))
	}

	// SCHEME-SWITCHING
	// LOCAL-THRESHOLD
	// AGGREGATION
	t0 := r.PrivateThreshold0.Threshold
	c := r.PrivateThreshold0.Normalization
	if score, err = s.SchemeSwitchingAndAggregatedLocalThreshold(resMerged, t0, c); err != nil {
		return nil, fmt.Errorf("s.SchemeSwitchingAndAggregatedLocalThreshold: %w", err)
	}

	s.PrintDebug("Aggregated Local-Threshold", score, 1.0)

	// GLOBAL THRESHOLD
	if score, err = s.GlobalThreshold(score, r.PrivateThreshold1.Threshold, rows); err != nil {
		return nil, fmt.Errorf("s.GlobalThreshold: %w", err)
	}

	s.PrintDebug("Global Threshold", score, 1.0)

	return score, nil
}

func (s Server) PrintDebug(msg string, input *rlwe.Ciphertext, scaling float64) {

	v := []float64{0, 0, 0, 0}

	switch len(input.Value[0].Coeffs[0]) {
	case s.ParamsEval.N():
		if s.DecEval != nil {
			if err := s.EcdEval.Decode(s.DecEval.DecryptNew(input), v); err != nil {
				panic(err)
			}
		}
	case s.ParamsPack.N():
		if s.DecPack != nil {
			if err := s.EcdPack.Decode(s.DecPack.DecryptNew(input), v); err != nil {
				panic(err)
			}
		}
	}

	for i := range v {
		v[i] *= scaling
	}

	fmt.Printf("%s: %v\n", msg, v)
}

func (s Server) SchemeSwitchingAndAggregatedLocalThreshold(resMerged []*rlwe.Ciphertext, t0, c *rlwe.Ciphertext) (score *rlwe.Ciphertext, err error) {

	paramsEval := s.ParamsEval
	score = hefloat.NewCiphertext(paramsEval, 1, paramsEval.MaxLevel())

	btp := s.Bootstrapper
	eval := btp.GetEvaluator()

	for i := range resMerged {

		ri := resMerged[i]

		var real, imag *rlwe.Ciphertext

		if err = RunTimed(fmt.Sprintf("Scheme-Switch ct[%d]", i), func() (err error) {
			if real, imag, err = btp.SchemeSwitch(ri); err != nil {
				return fmt.Errorf("btp.SchemeSwitch: %w", err)
			}
			return
		}); err != nil {
			return nil, err
		}

		s.PrintDebug(fmt.Sprintf("Scheme-Switch ct[%d][:N/2]", i), real, 1.0)
		s.PrintDebug(fmt.Sprintf("Scheme-Switch ct[%d][N/2:]", i), imag, 1.0)

		if err = RunTimed(fmt.Sprintf("Local-Threshold: ct[%d] (real)", i), func() (err error) {
			if err = s.LocalThreshold(real, t0, c, score); err != nil {
				return fmt.Errorf("s.LocalThreshold: %w", err)
			}
			return
		}); err != nil {
			return nil, err
		}

		s.PrintDebug(fmt.Sprintf("Score + Local-Threshold ct[%d][:N/2]", i), score, 1.0)

		if err = RunTimed(fmt.Sprintf("Local-Threshold: ct[%d] (imag)", i), func() (err error) {
			if err = s.LocalThreshold(imag, t0, c, score); err != nil {
				return fmt.Errorf("s.LocalThreshold: %w", err)
			}
			return
		}); err != nil {
			return nil, err
		}

		s.PrintDebug(fmt.Sprintf("Score + Local-Threshold ct[%d][N/2:]", i), score, 1.0)
	}

	// InnerSum
	if err = RunTimed("Inner-Sum", func() (err error) {
		if err = eval.InnerSum(score, 1, score.Slots(), score); err != nil {
			return fmt.Errorf("cmpEval.InnerSum: %w", err)
		}
		return
	}); err != nil {
		return nil, err
	}

	return
}

func (s Server) RingMerging(res []*rlwe.Ciphertext) (resMerged []*rlwe.Ciphertext, err error) {

	paramsPack := s.ParamsPack
	paramsEval := s.ParamsEval

	if err = RunTimed(fmt.Sprintf("Ring Merging LogN%d x %d -> LogN%d x %d", paramsPack.LogN(), len(res), paramsEval.LogN(), len(resMerged)), func() (err error) {

		ratio := paramsEval.N() / paramsPack.N()

		resMerged = make([]*rlwe.Ciphertext, (len(res)+ratio-1)/ratio)

		for i := range resMerged {

			start := i * ratio
			end := start + ratio

			if end > len(res) {
				end = len(res)
			}

			if resMerged[i], err = s.Merge(res[start:end], s.EvalRepack); err != nil {
				return fmt.Errorf("eval.Merge: %w", err)
			}
		}

		return
	}); err != nil {
		return nil, err
	}

	return
}

func (s Server) EncryptedLookupTablesAndRingPacking(db *Database, fi *TestVectors) (res []*rlwe.Ciphertext, err error) {

	eval := s.EvalRepack
	paramsPack := s.ParamsPack
	rows, cols := db.Dims()

	if err = RunTimed(fmt.Sprintf("Evaluating %dx%d TestVectors & Packing", rows, cols), func() (err error) {

		N := paramsPack.N()

		buffCts := make([]*rlwe.Ciphertext, N)

		for i := range buffCts {
			buffCts[i] = hefloat.NewCiphertext(paramsPack, 1, paramsPack.MaxLevel())
		}

		buffPoly := paramsPack.RingQ().NewPoly()

		res = make([]*rlwe.Ciphertext, (rows+N-1)/N)

		for i := range res {

			tmp := map[int]*rlwe.Ciphertext{}

			for j := 0; j < utils.Min(N, rows-i*N); j++ {

				if err = fi.Evaluate(paramsPack, db.GetRow(i*N+j), buffPoly, buffCts[j]); err != nil {
					return fmt.Errorf("fi.Evaluate: %w", err)
				}

				tmp[j] = buffCts[j]
			}

			if _, err = eval.Pack(tmp); err != nil {
				return fmt.Errorf("eval.Pack: %w", err)
			}

			res[i] = tmp[0].CopyNew()
		}

		for i := range res {
			ri := res[i]
			ri.IsBatched = false
			ri.Scale = paramsPack.DefaultScale()
			ri.LogDimensions.Rows = 0
			ri.LogDimensions.Cols = paramsPack.LogN() - 1
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return
}

func (s Server) LocalThreshold(input, t0, c *rlwe.Ciphertext, output *rlwe.Ciphertext) (err error) {

	polysThreshold0 := hefloat.NewMinimaxCompositePolynomial(MinimaxCompositePolynomialForSignThreshold0)

	eval := hefloat.NewComparisonEvaluator(s.ParamsEval, s.GetEvaluator(), s.Bootstrapper, polysThreshold0)

	if err = eval.Sub(input, t0, input); err != nil {
		return fmt.Errorf("eval.Sub: %w", err)
	}

	if err = eval.Add(input, 0.5, input); err != nil {
		return fmt.Errorf("eval.Add: %w", err)
	}

	if err = eval.MulRelin(input, c, input); err != nil {
		return fmt.Errorf("eval.MulRelin: %w", err)
	}

	if err = eval.Rescale(input, input); err != nil {
		return fmt.Errorf("eval.Rescale: %w", err)
	}

	if input, err = eval.Step(input); err != nil {
		return fmt.Errorf("eval.Step: %w", err)
	}

	if err = eval.Add(output, input, output); err != nil {
		return fmt.Errorf("eval.Add: %w", err)
	}

	return
}

func (s Server) GlobalThreshold(input, t1 *rlwe.Ciphertext, rows int) (output *rlwe.Ciphertext, err error) {

	if err = RunTimed("Global-Threshold", func() (err error) {

		polysThreshold1 := hefloat.NewMinimaxCompositePolynomial(MinimaxCompositePolynomialForSignThreshold1)

		eval := hefloat.NewComparisonEvaluator(s.ParamsEval, s.GetEvaluator(), s.Bootstrapper, polysThreshold1)

		if err = eval.Sub(input, t1, input); err != nil {
			return fmt.Errorf("eval.Sub: %w", err)
		}

		if input.Level() == 0 {
			if input, err = s.Bootstrap(input); err != nil {
				return fmt.Errorf("btp.Bootstrap: %w", err)
			}
		}

		if err = eval.Add(input, 0.5, input); err != nil {
			return fmt.Errorf("eval.Add: %w", err)
		}

		if err = eval.MulRelin(input, 1/float64(rows), input); err != nil {
			return fmt.Errorf("eval.MulRelin: %w", err)
		}

		if err = eval.Rescale(input, input); err != nil {
			return fmt.Errorf("eval.Rescale: %w", err)
		}

		if output, err = eval.Step(input); err != nil {
			return fmt.Errorf("eval.Step: %w", err)
		}

		return

	}); err != nil {
		return nil, err
	}

	return
}

func (s Server) Merge(cts []*rlwe.Ciphertext, eval *RepackEvaluator) (ct *rlwe.Ciphertext, err error) {

	if len(cts) > 1<<(eval.MaxLogN()-bits.Len64(uint64(len(cts[0].Value[0].Coeffs[0])-1))) {
		return nil, fmt.Errorf("too many ciphertexts")
	}

	for len(cts) != 1 {
		for i := 0; i < len(cts)>>1; i++ {
			if cts[i], err = eval.MergeNew(cts[2*i], cts[2*i+1]); err != nil {
				return nil, fmt.Errorf("eval.MergeNew(cts[2*i], cts[2*i+1]): %w", err)
			}
		}

		if len(cts)&1 == 1 {

			if cts[len(cts)>>1], err = eval.MergeNew(cts[len(cts)-1], nil); err != nil {
				return nil, fmt.Errorf("eval.MergeNew(cts[len(cts)-1], nil): %w", err)
			}

			cts = cts[:len(cts)>>1+1]
		} else {
			cts = cts[:len(cts)>>1]
		}
	}

	for bits.Len64(uint64(len(cts[0].Value[0].Coeffs[0])-1)) != eval.MaxLogN() {
		if cts[0], err = eval.MergeNew(cts[0], nil); err != nil {
			return nil, fmt.Errorf("eval.MergeNew(cts[0], nil): %w", err)
		}
	}

	return cts[0], nil
}
