// Command segredium is a self-hosted, AWS Secrets Manager API-compatible server.
package main

import (
	"os"

	"github.com/nathabonfim59/segredium/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr)) }
