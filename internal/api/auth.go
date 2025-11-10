package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

func (c *CC98) Login() error {
	data := url.Values{}
	data.Set("client_id", "9a1fd200-8687-44b1-4c20-08d50a96e5cd")
	data.Set("client_secret", "8b53f727-08e2-4509-8857-e34bf92b27f2")
	data.Set("grant_type", "password")
	data.Set("username", c.username)
	data.Set("password", c.password)
	data.Set("scope", "cc98-api openid offline_access")

	tokenURL := CC98OpenIDURL + "/connect/token"
	req, err := http.NewRequest("POST", tokenURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("登录失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return fmt.Errorf("解析响应失败: %w", err)
	}

	c.token = &token
	return nil
}
