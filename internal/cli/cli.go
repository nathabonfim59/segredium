// Package cli is segredium's subcommand registry (serve.go, ca.go).
package cli

import (
	"fmt"
	"io"
	"sort"
)

type Command struct {
	Name    string
	Summary string
	Run     func(args []string, stdout, stderr io.Writer) int
}

var commands = map[string]Command{}

func Register(c Command) {
	if _, dup := commands[c.Name]; dup {
		panic("cli: duplicate command " + c.Name)
	}
	commands[c.Name] = c
}

// Main dispatches args (without the program name) and returns the exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		return 2
	}
	c, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "segredium: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
	return c.Run(args[1:], stdout, stderr)
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: segredium <command> [flags]\n\ncommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "  %-10s %s\n", n, commands[n].Summary)
	}
}
