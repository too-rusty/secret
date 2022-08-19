

## Encryption Decryption package

1. Encryption of message

2. Decryption of message

3. Key generation


## Usage

```bash

go test ./... -v --race
# run all the tests

go build .
# build project

./secret-sharing generate --key secret
#generate key pair and store in secret and secret.pub files, these files should not exist before

./secret-sharing encrypt --key path.pub --in message.txt --out encrypted.txt
#encrypt a message where key is pub key path, in is inputfile path and out is outputfile path

./secret-sharing decrypt --key path --input encrypted.txt
#encrypt a message where key is priv key path and input is encrypted file path

```