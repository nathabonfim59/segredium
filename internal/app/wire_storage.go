package app

import (
	"github.com/nathabonfim59/segredium/internal/config"
	"github.com/nathabonfim59/segredium/internal/purge"
	"github.com/nathabonfim59/segredium/internal/store"
	"github.com/nathabonfim59/segredium/internal/store/filestore"
)

func init() {
	RegisterWorker("purge", purge.Run)
	RegisterStore("file", func(c *config.Config) (store.Store, error) {
		return filestore.Open(c.Storage.Path, c.Storage.KeyFile)
	})
}
