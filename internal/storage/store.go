package storage

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

var (
	errEmptyAccountID = errors.New("账号标识不能为空")
)

const (
	dirName      = ".cc98"
	tokensSubDir = "tokens"
	configName   = "config.json"
)

type Paths struct {
	BaseDir    string
	ConfigFile string
	TokensDir  string
}

func EnsurePaths() (*Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("获取用户目录失败: %w", err)
	}
	if home == "" {
		return nil, errors.New("未能确定用户主目录")
	}

	base := filepath.Join(home, dirName)
	tokens := filepath.Join(base, tokensSubDir)

	if err := mkdirIfNotExists(base); err != nil {
		return nil, fmt.Errorf("创建目录 %s 失败: %w", base, err)
	}
	if err := mkdirIfNotExists(tokens); err != nil {
		return nil, fmt.Errorf("创建目录 %s 失败: %w", tokens, err)
	}

	return &Paths{
		BaseDir:    base,
		ConfigFile: filepath.Join(base, configName),
		TokensDir:  tokens,
	}, nil
}

func mkdirIfNotExists(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.MkdirAll(path, 0o700)
}

func LoadConfig(paths *Paths) (Config, error) {
	if paths == nil {
		return Config{}, errors.New("paths 不能为空")
	}

	data, err := os.ReadFile(paths.ConfigFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return NewConfig(), nil
		}
		return Config{}, fmt.Errorf("读取配置失败: %w", err)
	}

	if len(data) == 0 {
		return NewConfig(), nil
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("解析配置失败: %w", err)
	}

	if cfg.Accounts == nil {
		cfg.Accounts = make(map[string]AccountConfig)
	}

	return cfg, nil
}

func SaveConfig(paths *Paths, cfg Config) error {
	if paths == nil {
		return errors.New("paths 不能为空")
	}

	if cfg.Accounts == nil {
		cfg.Accounts = make(map[string]AccountConfig)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	return writeFileAtomic(paths.ConfigFile, data, 0o600)
}

func TokenFilePath(paths *Paths, tokenFile string) (string, error) {
	if paths == nil {
		return "", errors.New("paths 不能为空")
	}
	if tokenFile == "" {
		return "", errors.New("token 文件名不能为空")
	}

	return filepath.Join(paths.TokensDir, tokenFile), nil
}

var base64Encoding = base64.RawURLEncoding

func GenerateTokenFileName(accountID string) (string, error) {
	if accountID == "" {
		return "", errEmptyAccountID
	}

	encoded := base64Encoding.EncodeToString([]byte(accountID))
	if encoded == "" {
		encoded = "account"
	}

	return encoded + ".json.enc", nil
}

func SaveTokenRecord(paths *Paths, accountID, tokenFile, masterPassword string, record TokenRecord) (string, error) {
	if paths == nil {
		return "", errors.New("paths 不能为空")
	}
	if masterPassword == "" {
		return "", errors.New("主密码不能为空")
	}

	if tokenFile == "" {
		name, err := GenerateTokenFileName(accountID)
		if err != nil {
			return "", err
		}
		tokenFile = name
	}

	payload, err := EncryptTokenRecord(masterPassword, record)
	if err != nil {
		return "", err
	}

	fullPath := filepath.Join(paths.TokensDir, tokenFile)
	if err := writeFileAtomic(fullPath, payload, 0o600); err != nil {
		return "", fmt.Errorf("写入 token 文件失败: %w", err)
	}

	return tokenFile, nil
}

func LoadTokenRecord(paths *Paths, tokenFile, masterPassword string) (*TokenRecord, error) {
	if paths == nil {
		return nil, errors.New("paths 不能为空")
	}
	if tokenFile == "" {
		return nil, errors.New("token 文件名不能为空")
	}
	if masterPassword == "" {
		return nil, errors.New("主密码不能为空")
	}

	fullPath := filepath.Join(paths.TokensDir, tokenFile)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, fmt.Errorf("读取 token 文件失败: %w", err)
	}

	record, err := DecryptTokenRecord(masterPassword, data)
	if err != nil {
		return nil, err
	}

	return record, nil
}

func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-cc98-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		return err
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Chmod(perm); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	if err := os.Rename(tmpName, path); err != nil {
		return err
	}

	return nil
}
