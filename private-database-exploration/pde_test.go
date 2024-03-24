package pde

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPDE(t *testing.T) {

	t.Log("Create Client")
	client := NewClient()

	t.Log("Generate Evaluation Keys (might take 30 to 60sec)")
	now := time.Now()
	evk, err := client.Init()
	require.NoError(t, err)

	t.Log("Generate Pre-Processing Matrix")

	// 16 dummy scoring function
	funcs := make([]Func, Features)
	for i := range funcs {
		funcs[i] = NewScoringFunction([2]float64{0, 4}, 2<<LogNPack, 1/float64(Scaling))
	}

	t.Log("Generating Encrypted Functions")
	tvs, err := client.GenEncryptedFunction(funcs)
	require.NoError(t, err)

	t.Log("Generating Private Threshold Parameters")
	privThresh0, err := client.GenPrivateThreshold(12, funcs)
	require.NoError(t, err)

	privThresh1, err := client.GenPrivateThreshold(float64(DBSize/100), nil)
	require.NoError(t, err)

	// Client request
	request := Request{
		EvaluationKeys:      &evk,
		TestVectors:         &tvs,
		PrivateThreshold0:   &privThresh0,
		PrivateThreshold1:   &privThresh1,
	}

	fmt.Printf("Client Init(): %s\n", time.Since(now))

	t.Log("Instantiating Server")
	server := NewServer()
	server.SkDebug = client.Ski           // Enables to print intermediate values
	server.SecretKeyBootstrapping = false // Use dummy bootstrapper during threshold (much faster),
	// only possible if server.SkDebug is set
	t.Log("Loading Dataset")
	db := NewDatabase(DBSize, Features)

	btp, err := NewBootstrappingEvaluator(request)
	require.NoError(t, err)

	t.Log("Processing Request")
	score, err := server.ProcessRequest(request, &db, btp)
	require.NoError(t, err)

	t.Log("Client Response Decryption")
	v, err := client.Decrypt(score)
	require.NoError(t, err)

	fmt.Printf("Result: %10.7f\n", v[0])
}
