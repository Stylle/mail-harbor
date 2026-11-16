package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
var webhookVariable = regexp.MustCompile(`\{\{\s*([a-zA-Z]+)\s*\}\}`)

func validateHeaders(raw string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}, nil
	}
	if len(raw) > 16000 {
		return nil, errors.New("自定义请求头过长")
	}
	headers := map[string]string{}
	if json.Unmarshal([]byte(raw), &headers) != nil || len(headers) > 30 {
		return nil, errors.New("请求头必须是JSON字符串对象")
	}
	for key, value := range headers {
		if !headerName.MatchString(key) || strings.ContainsAny(value, "\r\n\x00") || len(value) > 4096 {
			return nil, errors.New("请求头包含非法名称或换行")
		}
		switch strings.ToLower(key) {
		case "host", "cookie", "content-length", "connection", "transfer-encoding", "proxy-authorization", "proxy-connection", "upgrade", "te", "trailer":
			return nil, errors.New("不允许覆盖连接控制或Cookie请求头")
		}
	}
	return headers, nil
}
func renderWebhook(ch Channels, payload any) ([]byte, string, error) {
	data, e := json.Marshal(payload)
	if e != nil {
		return nil, "", e
	}
	vars := map[string]any{}
	_ = json.Unmarshal(data, &vars)
	vars["fields"] = payload
	vars["title"] = "新邮件通知"
	vars["text"] = "你收到一封新邮件"
	if v, ok := vars["subject"]; ok {
		vars["title"] = v
	}
	if v, ok := vars["body"]; ok {
		vars["text"] = v
	}
	for _, k := range []string{"from", "subject", "body", "account", "event", "deliveryId"} {
		if _, ok := vars[k]; !ok {
			vars[k] = ""
		}
	}
	replace := func(s string) string {
		return webhookVariable.ReplaceAllStringFunc(s, func(token string) string {
			key := webhookVariable.FindStringSubmatch(token)[1]
			value, ok := vars[key]
			if !ok {
				return ""
			}
			switch v := value.(type) {
			case string:
				return v
			default:
				b, _ := json.Marshal(v)
				return string(b)
			}
		})
	}
	contentType := "application/json"
	if ch.WebhookBodyType == "text" {
		contentType = "text/plain; charset=utf-8"
		data = []byte(fmt.Sprint(vars["text"]))
	}
	if ch.WebhookBody == "" {
		return data, contentType, nil
	}
	if len(ch.WebhookBody) > 64000 {
		return nil, "", errors.New("正文模板过长")
	}
	if ch.WebhookBodyType == "text" {
		return []byte(replace(ch.WebhookBody)), contentType, nil
	}
	var template any
	if json.Unmarshal([]byte(ch.WebhookBody), &template) != nil {
		return nil, "", errors.New("正文模板必须是合法JSON，变量放在字符串引号内")
	}
	var walk func(any) any
	walk = func(value any) any {
		switch v := value.(type) {
		case string:
			if strings.TrimSpace(v) == "{{fields}}" {
				return payload
			}
			return replace(v)
		case []any:
			for i, x := range v {
				v[i] = walk(x)
			}
			return v
		case map[string]any:
			out := map[string]any{}
			for k, x := range v {
				out[k] = walk(x)
			}
			return out
		default:
			return value
		}
	}
	data, e = json.Marshal(walk(template))
	return data, contentType, e
}
func validateWebhookSettings(ch Channels, headers string) error {
	if ch.WebhookMethod != "" && ch.WebhookMethod != http.MethodPost && ch.WebhookMethod != http.MethodPut && ch.WebhookMethod != http.MethodPatch && ch.WebhookMethod != http.MethodGet {
		return errors.New("不支持的Webhook请求方式")
	}
	if ch.WebhookBodyType != "" && ch.WebhookBodyType != "json" && ch.WebhookBodyType != "text" {
		return errors.New("正文类型只能为JSON或Text")
	}
	if _, e := validateHeaders(headers); e != nil {
		return e
	}
	_, _, e := renderWebhook(ch, map[string]any{"event": "mail.test", "text": "test"})
	return e
}
func (s *Store) webhookReady(ch Channels) (Channels, error) {
	plain, e := s.decrypt(ch.WebhookHeaders)
	if e != nil {
		return ch, errors.New("请求头配置无法读取")
	}
	ch.WebhookHeaders = plain
	return ch, nil
}
