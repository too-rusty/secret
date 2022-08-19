package cli

import (
	"flag"
	"fmt"
	"io/ioutil"
	"secret-sharing/keymanager"
)

type encryptCommand struct {
	fs *flag.FlagSet
	km keymanager.KeyManagerIface

	key     string
	in, out string
}

var _ Runner = &encryptCommand{}

func NewEncryptCommand() *encryptCommand {
	ec := &encryptCommand{
		fs: flag.NewFlagSet("encrypt", flag.ContinueOnError),
	}
	ec.fs.StringVar(&ec.key, "key", "", "pub key path")
	ec.fs.StringVar(&ec.in, "in", "", "input message file path")
	ec.fs.StringVar(&ec.out, "out", "", "output file path")
	return ec

}

func (g encryptCommand) Run() error {
	data, err := ioutil.ReadFile(g.in)
	if err != nil {
		return err
	}

	encryptedData, err := g.km.EncryptData(data)
	if err != nil {
		return err
	}

	outFile := "encrypted.txt"
	if g.out != "" {
		outFile = g.out
	}
	fmt.Println("message incrypted in file: ", outFile)
	return ioutil.WriteFile(outFile, encryptedData, 0777)
}

func (g encryptCommand) Name() string { return g.fs.Name() }

func (g *encryptCommand) Init(args []string) (err error) {

	if err = g.fs.Parse(args); err != nil {
		return
	}
	g.km, err = keymanager.NewKeyManager(g.key, keymanager.WRITE_MODE)
	if err != nil {
		return
	}

	return
}

/*

./secret-sharing encrypt --key path.pub --in inputFile --out outputFile

encrypt a message where key is public key, in is inputfile path and out is outputfile path

*/
