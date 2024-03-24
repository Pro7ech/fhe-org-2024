package pde

import (
	"math"
	"math/rand"

	"gonum.org/v1/gonum/mat"
)

type Database struct {
	*mat.Dense
}

func NewDatabase(p, h int) Database {

	//#nosec G404
	r := rand.New(rand.NewSource(0))

	m := make([]float64, p*h)

	for i := range m {
		n := math.Abs(r.NormFloat64())

		for n >= 1 {
			n = math.Abs(r.NormFloat64())
		}

		m[i] = n + 1
	}

	return Database{
		Dense: mat.NewDense(p, h, m),
	}
}

// Size returns the number of rows in the DB.
func (db Database) Size() int {
	rows, _ := db.Dims()
	return rows
}

func (d Database) GetRow(i int) []float64 {
	_, cols := d.Dims()
	return d.RawMatrix().Data[i*cols : (i+1)*cols]
}
