package pde

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v5/core/rlwe"
)

// SchemeSwitch takes Enc(m(X)) at modulus Q[0] and returns Enc(Encode(m(X))) at modulus Q[L].
func (eval BootstrappingEvaluator) SchemeSwitch(input *rlwe.Ciphertext) (output0, output1 *rlwe.Ciphertext, err error) {

	if output0, _, err = eval.ScaleDown(input); err != nil {
		return nil, nil, fmt.Errorf("eval.ScaleDown: %w", err)
	}

	if output0, err = eval.ModUp(output0); err != nil {
		return nil, nil, fmt.Errorf("eval.ModUp: %w", err)
	}

	if output0, output1, err = eval.CoeffsToSlots(output0); err != nil {
		return nil, nil, fmt.Errorf("eval.CoeffsToSlots: %w", err)
	}

	output0.IsBatched = true

	if output0, err = eval.EvalMod(output0); err != nil {
		return nil, nil, fmt.Errorf("eval.EvalMod(output0): %w", err)
	}

	for output0.Level() != eval.ResidualParameters.MaxLevel() {
		eval.Evaluator.Evaluator.DropLevel(output0, 1)
	}

	if err = eval.Evaluator.Evaluator.Mul(output0, Scaling>>7, output0); err != nil {
		return nil, nil, fmt.Errorf("eval.Mul: %w", err)
	}

	if output1 != nil {

		output1.IsBatched = true

		if output1, err = eval.EvalMod(output1); err != nil {
			return nil, nil, fmt.Errorf("eval.EvalMod(output1): %w", err)
		}

		for output1.Level() != eval.ResidualParameters.MaxLevel() {
			eval.Evaluator.Evaluator.DropLevel(output1, 1)
		}

		if err = eval.Evaluator.Evaluator.Mul(output1, Scaling>>7, output1); err != nil {
			return nil, nil, fmt.Errorf("eval.Mul: %w", err)
		}
	}

	return
}
