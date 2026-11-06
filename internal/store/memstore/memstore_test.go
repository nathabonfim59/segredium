package memstore_test

import (
	"testing"

	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/store/memstore"
	"github.com/nathabonfim59/segredium/internal/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return memstore.New() })
}
