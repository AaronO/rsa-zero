package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
)

// Size of RSA keys we want to generate
var SIZES []int = []int{
	128,
	256,
	512,
	1024,
	2048,
	4096,
}

func main() {
	for _, size := range SIZES {
		fmt.Println(size)
		if err := writeKeys(size); err != nil {
			fmt.Println(fmt.Errorf("Failed to write private key (%d) : %s", size, err))
		}
	}

	fmt.Println("Done :)")
}

func writeKeys(size int) error {
	private, err := generateKey(size)
	if err != nil {
		return err
	}
	// Marshal private key
	privateData, err := marshalPrivate(private)
	if err != nil {
		return err
	}
	// Marshal public key
	publicData, err := marshalPublic(&private.PublicKey)
	if err != nil {
		return err
	}

	// Write private key
	if err := ioutil.WriteFile(
		fmt.Sprintf("./rsa_%d.key", size),
		privateData,
		0644,
	); err != nil {
		return err
	}

	// Write public key
	if err := ioutil.WriteFile(
		fmt.Sprintf("./rsa_%d.pub", size),
		publicData,
		0644,
	); err != nil {
		return err
	}

	return nil
}

func generateKey(size int) (*rsa.PrivateKey, error) {
	var reader io.Reader = NewZeroReader(int64(size))
	return rsa.GenerateKey(reader, size)
}

func marshalPrivate(key *rsa.PrivateKey) ([]byte, error) {
	data := x509.MarshalPKCS1PrivateKey(key)
	return pemEncode(data, "RSA PRIVATE KEY"), nil
}

func marshalPublic(key *rsa.PublicKey) ([]byte, error) {
	data, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pemEncode(data, "PUBLIC KEY"), nil
}

func pemEncode(data []byte, pemType string) []byte {
	block := pem.Block{
		Bytes: data,
		Type:  pemType,
	}

	return pem.EncodeToMemory(&block)
}

// ZeroReader always returns zeroed buffers
type ZeroReader struct {
	Source rand.Source
}

func NewZeroReader(seed int64) *ZeroReader {
	return &ZeroReader{
		Source: rand.NewSource(seed),
	}
}

func (z *ZeroReader) Read(b []byte) (int, error) {
	// Zero the byte buffer
	for i, _ := range b {
		b[i] = byte(z.Source.Int63())
	}

	return len(b), nil
}
