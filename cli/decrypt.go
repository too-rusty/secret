package cli

import (
	"flag"
	"fmt"
	"io/ioutil"
	"secret-sharing/keymanager"
)

type decryptCommand struct {
	fs *flag.FlagSet
	km keymanager.KeyManagerIface

	key     string
	in, out string
}

var _ Runner = &decryptCommand{}

func NewDecryptCommand() *decryptCommand {
	ec := &decryptCommand{
		fs: flag.NewFlagSet("decrypt", flag.ContinueOnError),
	}
	ec.fs.StringVar(&ec.key, "key", "", "pub key path")
	ec.fs.StringVar(&ec.in, "in", "", "input message file path")
	ec.fs.StringVar(&ec.out, "out", "", "output file path")
	return ec

}

func (g decryptCommand) Run() error {
	data, err := ioutil.ReadFile(g.in)
	if err != nil {
		return err
	}

	decryptedData, err := g.km.DecryptData(data)
	if err != nil {
		return err
	}

	if g.out != "" {
		if err := ioutil.WriteFile(g.out, decryptedData, 0777); err != nil {
			return err
		}
	}

	fmt.Printf("Decrypted Data: %s\n", decryptedData)

	return nil
}

func (g decryptCommand) Name() string { return g.fs.Name() }

func (g *decryptCommand) Init(args []string) (err error) {

	if err = g.fs.Parse(args); err != nil {
		return
	}
	g.km, err = keymanager.NewKeyManager(g.key, keymanager.READ_MODE)
	if err != nil {
		return
	}

	return
}

/*

./secret-sharing decrypt --key secret --in inputFile

#decrypt a message where key is priv key, in is encrypted inputfile path and out is outputfile path
if nothing is specified then its print it to terminal

*/
