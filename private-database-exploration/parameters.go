package pde

import (
	"github.com/tuneinsight/lattigo/v5/he/hefloat"
	"github.com/tuneinsight/lattigo/v5/he/hefloat/bootstrapping"
	"github.com/tuneinsight/lattigo/v5/ring"
	"github.com/tuneinsight/lattigo/v5/utils"
)

var LogNPack = 12
var LogNEval = 16
var LogScale = 45
var Scaling = 1 << 16
var DBSize = 1 << 14
var Features = 16

var ParametersLiteralLogN16 = hefloat.ParametersLiteral{
	LogN:            LogNEval,
	LogQ:            []int{60, LogScale, LogScale, LogScale, LogScale, LogScale, LogScale, LogScale, LogScale},
	LogP:            []int{48, 55, 55},
	LogDefaultScale: LogScale,
	Xs:              ring.Ternary{H: 192},
}

var BootstrappingParametersLiteral = bootstrapping.ParametersLiteral{
	LogN: utils.Pointy(LogNEval),
	LogP: []int{61, 61, 61, 61, 61},
	Xs:   ring.Ternary{H: 192},
}
