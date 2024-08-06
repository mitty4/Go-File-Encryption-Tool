package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)
func main() {
	if len(os.Args) < 4 {
		fmt.Println("Usage file-encrypt <encrypt/decrypt> <input file> <output file>")
		os.Exit(1)
	}

	action := os.Args[1]
	inputFile := os.Args[2]
	outputFile := os.Args[3]

	key := []byte(os.Getenv("FILEENCRYPT"))

	switch action {
	case "encrypt":
		encryptFile(inputFile, outputFile, key)
	case "decrypt":
		decryptFile(inputFile, outputFile, key)
	default:
		fmt.Println("that ain't right:", action)
		os.Exit(1)
	}
}

func encryptFile(inputFile, outputFile string, key []byte) {
	plaintext, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Println("Problem!:", err)
		os.Exit(1)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error making cipher!:", err)
	}


    gcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println("Error creating GCM:", err)
        os.Exit(1)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
        fmt.Println("Error generating nonce:", err)
        os.Exit(1)
    }

    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

    if err := ioutil.WriteFile(outputFile, ciphertext, 0644); err != nil {
        fmt.Println("Error writing file:", err)
        os.Exit(1)
    }

    fmt.Println("File encrypted successfully")
}

func decryptFile(inputFile, outputFile string, key []byte) {
    ciphertext, err := ioutil.ReadFile(inputFile)
    if err != nil {
        fmt.Println("Error reading file:", err)
        os.Exit(1)
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        fmt.Println("Error creating cipher:", err)
        os.Exit(1)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println("Error creating GCM:", err)
        os.Exit(1)
    }

    nonceSize := gcm.NonceSize()
    if len(ciphertext) < nonceSize {
        fmt.Println("Ciphertext too short")
        os.Exit(1)
    }

    nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        fmt.Println("Error decrypting file:", err)
        os.Exit(1)
    }

    if err := ioutil.WriteFile(outputFile, plaintext, 0644); err != nil {
        fmt.Println("Error writing file:", err)
        os.Exit(1)
    }

    fmt.Println("File decrypted successfully")
}
