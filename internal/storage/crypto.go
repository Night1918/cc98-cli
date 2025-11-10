package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	keyLength      = 32
	saltLength     = 16
	gcmNonceLength = 12

	scryptN = 1 << 15
	scryptR = 8
	scryptP = 1
)

type encryptedPayload struct {
	Version    int               `json:"version"`
	KDF        string            `json:"kdf"`
	Params     map[string]int    `json:"params,omitempty"`
	Salt       string            `json:"salt"`
	Nonce      string            `json:"nonce"`
	Ciphertext string            `json:"ciphertext"`
	CreatedAt  time.Time         `json:"created_at"`
	Meta       map[string]string `json:"meta,omitempty"`
}

var (
	errInvalidPayload = errors.New("无效的加密数据")
)

func EncryptTokenRecord(masterPassword string, record TokenRecord) ([]byte, error) {
	if masterPassword == "" {
		return nil, errors.New("主密码不能为空")
	}

	salt, err := randomBytes(saltLength)
	if err != nil {
		return nil, fmt.Errorf("生成盐失败: %w", err)
	}

	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("派生密钥失败: %w", err)
	}

	plaintext, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("序列化 token 失败: %w", err)
	}

	ciphertext, nonce, err := encryptAESGCM(key, plaintext)
	if err != nil {
		return nil, err
	}

	payload := encryptedPayload{
		Version:    1,
		KDF:        "scrypt",
		Params:     map[string]int{"N": scryptN, "r": scryptR, "p": scryptP},
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt:  time.Now().UTC(),
	}

	return json.Marshal(payload)
}

func DecryptTokenRecord(masterPassword string, data []byte) (*TokenRecord, error) {
	if masterPassword == "" {
		return nil, errors.New("主密码不能为空")
	}

	var payload encryptedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("解析加密数据失败: %w", err)
	}

	if payload.Version != 1 {
		return nil, fmt.Errorf("不支持的加密版本: %d", payload.Version)
	}
	if payload.KDF != "scrypt" {
		return nil, fmt.Errorf("不支持的密钥派生函数: %s", payload.KDF)
	}

	salt, err := base64.StdEncoding.DecodeString(payload.Salt)
	if err != nil || len(salt) == 0 {
		return nil, errInvalidPayload
	}

	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil || len(nonce) == 0 {
		return nil, errInvalidPayload
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return nil, errInvalidPayload
	}

	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("派生密钥失败: %w", err)
	}

	plaintext, err := decryptAESGCM(key, nonce, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	var record TokenRecord
	if err := json.Unmarshal(plaintext, &record); err != nil {
		return nil, fmt.Errorf("解析 token 失败: %w", err)
	}

	return &record, nil
}

func deriveKey(masterPassword string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(masterPassword), salt, scryptN, scryptR, scryptP, keyLength)
}

func encryptAESGCM(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 AES 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	nonce, err := randomBytes(gcmNonceLength)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func decryptAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES 失败: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
