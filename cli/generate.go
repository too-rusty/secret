package cli

import (
	"flag"
	"secret-sharing/keymanager"
)

type generateCommand struct {
	fs  *flag.FlagSet
	km  keymanager.KeyManagerIface
	key string
}

var _ Runner = &generateCommand{}

func NewGenerateCommand() *generateCommand {
	gc := &generateCommand{
		fs: flag.NewFlagSet("generate", flag.ContinueOnError),
	}
	gc.fs.StringVar(&gc.key, "key", "", "key to store the secret file")
	return gc

}

func (g generateCommand) Run() error   { return g.km.Generate() }
func (g generateCommand) Name() string { return g.fs.Name() }

func (g *generateCommand) Init(args []string) (err error) {

	if err = g.fs.Parse(args); err != nil {
		return
	}
	g.km, err = keymanager.NewKeyManager(g.key, keymanager.GEN_MODE)
	if err != nil {
		return
	}

	return
}

// cmd: ./secret-sharing generate --key keyPath
