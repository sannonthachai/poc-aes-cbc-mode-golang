package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/mergermarket/go-pkcs7"
)

// Cipher key must be 32 chars long because block size is 16 bytes
const SECRET = "KaPdSgVkYp3s6v9y$B&E(H+MbQeThWmZ"
const IV = "3F4528482B4D6251"

type Credential struct {
	TranId   string `json:"tran_id"`
	QrCode   string `json:"qr_code"`
	IdCard   string `json:"id_card"`
	MobileNo string `json:"mobile_no,omitempty"`
}

type CipherText struct {
	CipherText string `json:"cipher_text"`
}

func main() {
	mockJson, _ := ioutil.ReadFile("mock.json")
	compactedBuffer := new(bytes.Buffer)
	err := json.Compact(compactedBuffer, mockJson)
	if err != nil {
		fmt.Println(err)
	}

	plainText := compactedBuffer.String()
	fmt.Println("plainText", plainText)

	encrypted, err := Encrypt(plainText)
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to encrypt: %s - %s", plainText, err.Error()))
	}

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		fmt.Println(fmt.Sprintf("Failed to decrypt: %s - %s", plainText, err.Error()))
	}

	fmt.Println("encrypt", encrypted)
	fmt.Println("decrypted", decrypted)

	e := echo.New()
	e.POST("/", func(c echo.Context) error {
		var bodyBytes []byte
		if c.Request().Body != nil {
			bodyBytes, _ = ioutil.ReadAll(c.Request().Body)
		}

		cipherText := CipherText{}
		json.Unmarshal(bodyBytes, &cipherText)

		de, err := Decrypt(cipherText.CipherText)
		if err != nil {
			fmt.Println(fmt.Sprintf("Failed to decrypt: %s - %s", plainText, err.Error()))
		}

		c.Request().Body = ioutil.NopCloser(bytes.NewBuffer([]byte(de)))

		cre := Credential{}
		if err := c.Bind(&cre); err != nil {
			fmt.Println("can not bind struct")
		}

		fmt.Println("bind data ->", cre)

		return c.String(http.StatusOK, "Hello, World!")
	})
	e.Logger.Fatal(e.Start(":1323"))
}

// Encrypt encrypts plain text string into cipher text string
func Encrypt(unencrypted string) (string, error) {
	key := []byte(SECRET)
	plainText := []byte(unencrypted)

	plainText, err := pkcs7.Pad(plainText, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf(`plainText: "%s" has error`, plainText)
	}
	if len(plainText)%aes.BlockSize != 0 {
		err := fmt.Errorf(`plainText: "%s" has the wrong block size`, plainText)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, len(plainText))
	iv := []byte(IV)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, plainText)

	return fmt.Sprintf("%x", cipherText), nil
}

// Decrypt decrypts cipher text string into plain text string
func Decrypt(encrypted string) (string, error) {
	key := []byte(SECRET)
	cipherText, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipherText too short")
	}
	iv := []byte(IV)
	if len(cipherText)%aes.BlockSize != 0 {
		panic("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, _ = pkcs7.Unpad(cipherText, aes.BlockSize)
	return fmt.Sprintf("%s", cipherText), nil
}
