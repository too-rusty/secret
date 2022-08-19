package cli

import (
	"errors"
	"os"
)

var errNoSubcommand = errors.New("no subcommand specified")
var errUnknownCommand = errors.New("unknown command")

type cli struct {
	runners []Runner
}

func NewCLI(runners []Runner) cli {
	return cli{
		runners: runners,
	}
}

func (c cli) Execute() error {
	args := os.Args

	if len(args) < 2 {
		return errNoSubcommand
	}

	args = args[1:]

	cmd := args[0]

	for _, runner := range c.runners {
		if runner.Name() == cmd {
			runner.Init(args[1:])
			return runner.Run()
		}
	}

	return errUnknownCommand

}
