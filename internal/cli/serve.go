package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/nathabonfim59/segredium/internal/api"
	"github.com/nathabonfim59/segredium/internal/app"
	"github.com/nathabonfim59/segredium/internal/config"
)

// Version is set at build time (-ldflags "-X .../internal/cli.Version=...").
var Version = "dev"

func init() {
	Register(Command{Name: "serve", Summary: "run the Secrets Manager-compatible server", Run: serve})
	Register(Command{Name: "version", Summary: "print the version", Run: func(_ []string, out, _ io.Writer) int {
		fmt.Fprintln(out, "segredium", Version)
		return 0
	}})
	Register(Command{Name: "operations", Summary: "list implemented API operations", Run: func(_ []string, out, _ io.Writer) int {
		for _, op := range api.Operations() {
			fmt.Fprintln(out, op)
		}
		return 0
	}})
}

func serve(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", os.Getenv("SEGREDIUM_CONFIG"), "path to the YAML config file (env SEGREDIUM_CONFIG)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cfg.Server.LogLevel))
	log := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: lvl}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("exit", "err", err)
		return 1
	}
	return 0
}
