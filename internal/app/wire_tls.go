package app

import (
	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/ca"
	"github.com/nathabonfim59/segredium/internal/config"
	"github.com/nathabonfim59/segredium/internal/sm"
)

// tls.mode=ca serves certificates minted by the built-in local CA, per SNI hostname.
func init() {
	RegisterTLS("ca", func(c *config.Config, _ *sm.Deps) (api.TLSProvider, error) {
		return ca.NewCA(c)
	})
}
