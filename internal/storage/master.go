package storage

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

var ErrMasterMismatch = errors.New("主密码不正确")

func EnsureMaster(cfg *Config, masterPassword string) error {
	if cfg == nil {
		return errors.New("cfg 不能为空")
	}
	if masterPassword == "" {
		return errors.New("主密码不能为空")
	}

	if cfg.Master == nil {
		mi, err := newMasterInfo(masterPassword)
		if err != nil {
			return err
		}
		cfg.Master = mi
		return nil
	}

	ok, err := verifyMaster(masterPassword, cfg.Master)
	if err != nil {
		return err
	}
	if !ok {
		return ErrMasterMismatch
	}
	return nil
}

func newMasterInfo(masterPassword string) (*MasterInfo, error) {
	salt, err := randomBytes(saltLength)
	if err != nil {
		return nil, fmt.Errorf("生成主密码盐失败: %w", err)
	}

	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return nil, fmt.Errorf("派生主密码密钥失败: %w", err)
	}

	h := sha256.Sum256(key)
	return &MasterInfo{
		KDF:       "scrypt",
		Params:    map[string]int{"N": scryptN, "r": scryptR, "p": scryptP},
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Verifier:  base64.StdEncoding.EncodeToString(h[:]),
		CreatedAt: time.Now().UTC(),
	}, nil
}

func verifyMaster(masterPassword string, mi *MasterInfo) (bool, error) {
	if mi == nil {
		return false, errors.New("MasterInfo 为空")
	}
	if mi.KDF != "scrypt" {
		return false, fmt.Errorf("不支持的 KDF: %s", mi.KDF)
	}

	salt, err := base64.StdEncoding.DecodeString(mi.Salt)
	if err != nil {
		return false, fmt.Errorf("解析主密码盐失败: %w", err)
	}

	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return false, fmt.Errorf("派生主密码密钥失败: %w", err)
	}

	h := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(h[:]) == mi.Verifier, nil
}
