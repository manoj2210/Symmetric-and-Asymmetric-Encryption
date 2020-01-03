package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

//Struct for Storing Decoded Message
type Message struct {
	De string
}

const (
	PrivateKeyPath      string = "../rsa_4096_priv.pem"
	MessageKeyDelimiter string = ":::"
)

var PrivateKey *rsa.PrivateKey

func init() {
	// read the private key for data decryption
	keyFile, err := ioutil.ReadFile(PrivateKeyPath)
	if err != nil {
		log.Fatal("Error reading private key")
	}
	// get the private key pem block data
	block, _ := pem.Decode(keyFile)
	if block == nil {
		log.Fatal("Error reading private key")
	}
	// decode the RSA private key
	PrivateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("Could not decode our ")
	}
}
func main() {
	// please note, that you need some method to
	// receive the data from somewhere (i.e. server, function call)
	// create a channel to receive encrypted data
	// that will then be decrypted
	decoderChannel := make(chan string)
	// create a channel to receive decrypted data
	messageChannel := make(chan Message)
	// run our decoding function in a separate go routine

	go decode(decoderChannel, messageChannel)
	// do something with the decrypted messages
	// (using a for loop to never stop receiving data
	for {
		reader := bufio.NewReader(os.Stdin)
		text, _ := reader.ReadString('\n')
		decoderChannel <- text
		fmt.Println(<-messageChannel)
	}
	// we should never get to this code as the receiving
	// channel in the line before is blocking forever
	// log.Println("this should never be called")
}

// decode is used to decode encrypted data
func decode(decoderChannel <-chan string, messageChannel chan<- Message) {

	// run a loop to never stop receiving data on our
	// decoder channel
	for {
		// split the received message
		// (encrypted key is appended to data)
		// data[0]:key, data[1]:message
		// the MessageKeyDelimiter is saved as constant
		encrypted := strings.Split(<-decoderChannel, MessageKeyDelimiter)
		// fmt.Println(encrypted)
		// decrypt the AES-encryption-key with our private key
		keyAndIv := decryptRSA(encrypted[0])
		// split the key and its components
		keyComponents := strings.Split(keyAndIv, MessageKeyDelimiter)
		// decrypt the AES encrypted data using
		// the components from before
		message := decryptAES(keyComponents[0], keyComponents[1], encrypted[1])

		data := Message{string(message)}
		// create a new data str
		// pass the data to our message channel for further work
		messageChannel <- data
	}
}

// decryptRSA will decrypt an rsa-encrypted string using the
// private key loaded in the init-function from the specified
// private-key-file. It will return the decrypted data as string.
func decryptRSA(encrypted string) string {

	// decode our encrypted string into cipher bytes
	cipheredValue, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		log.Println("error: decoding string (rsa)")
		return ""
	}
	// decrypt the data
	var out []byte
	out, err = rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, cipheredValue)
	if err != nil {
		log.Println("error: reading encrypted data")
		return ""
	}
	return string(out)
}

// decryptAES will decrpyt an encrypted message using the
// given key and iv. It will return the decrypted information
// as byte-slice
func decryptAES(keyString string, ivString string, encrypted string) []byte {
	// decode from hex to byte
	key, _ := hex.DecodeString(keyString)
	iv, _ := hex.DecodeString(ivString)
	// decode our encrypted string into bytes
	cipheredMessage, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		log.Println("error: decoding string (aes)")
	}
	// create a new cipher block from our key
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil
	}
	// cbc message must be multiple of aes blocksize
	if len(cipheredMessage) < aes.BlockSize {
		log.Println("error: ciphertext too short")
	}
	// the iv is prepended to the actual message/data
	cipherText := cipheredMessage[aes.BlockSize:]
	// decrypt the data
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	return cipherText
}
