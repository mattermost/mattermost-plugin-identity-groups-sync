package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/pkg/errors"
)

func encode(encrypted []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(encrypted)))
	base64.URLEncoding.Encode(encoded, encrypted)
	return encoded
}

func decode(encoded []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(encoded)))
	n, err := base64.URLEncoding.Decode(decoded, encoded)
	if err != nil {
		return nil, err
	}
	return decoded[:n], nil
}

func Encrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), errors.Wrap(err, "could not create a cipher block, check key")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte(""), err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte(""), err
	}

	sealed := aesgcm.Seal(nil, nonce, data, nil)
	return encode(append(nonce, sealed...)), nil
}

func Decrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), errors.Wrap(err, "could not create a cipher block, check key")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte(""), err
	}

	decoded, err := decode(data)
	if err != nil {
		return []byte(""), err
	}

	nonceSize := aesgcm.NonceSize()
	if len(decoded) < nonceSize {
		return []byte(""), errors.New("token too short")
	}

	nonce, encrypted := decoded[:nonceSize], decoded[nonceSize:]
	plain, err := aesgcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return []byte(""), err
	}

	return plain, nil
}

func GenerateSecret() (string, error) {
	b := make([]byte, 256)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	s := base64.RawStdEncoding.EncodeToString(b)

	s = s[:32]

	return s, nil
}
