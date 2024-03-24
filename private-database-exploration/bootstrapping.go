package pde

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

type Bootstrapper interface {
	he.Bootstrapper[rlwe.Ciphertext]
	SchemeSwitch(input *rlwe.Ciphertext) (output0, output1 *rlwe.Ciphertext, err error)
	GetEvaluator() *hefloat.Evaluator
}

type BootstrappingEvaluator struct {
	bootstrapping.Evaluator
}

func NewBootstrappingEvaluator(r Request) (btp Bootstrapper, err error) {

	paramsEval := hefloat.Parameters{Parameters: ckks.Parameters{Parameters: *r.Parameters[LogNEval].GetRLWEParameters()}}

	var btpParams bootstrapping.Parameters
	if btpParams, err = bootstrapping.NewParametersFromLiteral(paramsEval, BootstrappingParametersLiteral); err != nil {
		return nil, fmt.Errorf("bootstrapping.NewParametersFromLiteral: %w", err)
	}

	var eval *bootstrapping.Evaluator
	if eval, err = bootstrapping.NewEvaluator(btpParams, &r.EvaluationKeys.EvaluationKeys); err != nil {
		return nil, fmt.Errorf("bootstrapping.NewEvaluator: %w", err)
	}

	return BootstrappingEvaluator{Evaluator: *eval}, nil
}

func (eval BootstrappingEvaluator) GetEvaluator() *hefloat.Evaluator {
	return eval.Evaluator.Evaluator
}
