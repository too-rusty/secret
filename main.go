package main

import (
	"log"
	"secret-sharing/cli"
)

func main() {

	runners := []cli.Runner{
		cli.NewGenerateCommand(),
		cli.NewEncryptCommand(),
		cli.NewDecryptCommand(),
	}

	cli := cli.NewCLI(runners)
	if err := cli.Execute(); err != nil {
		log.Fatalf("ERROR OCCURED: %s\n", err.Error())
	}
}

/*

Steps to run

1 go build .
2 ./secret-sharing generate -key alice
3 ./secret-sharing generate -key bob
4 ./secret-sharing encrypt -in message.txt -key alice
5 ./secret-sharing decrypt -in encrypted.txt -key bob
6 ./secret-sharing decrypt -in encrypted.txt -key alice
7 go test ./... -v --race


generate alice and bob keys
encrypt the message using alice's keys
try decrypting the message using bob's keys only to result in an error
decrypt the encrypted message using alice keys and see the out put on the screen

or

simply run the tests

*/
