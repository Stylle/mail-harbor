package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	store       *Store
	mu          sync.Mutex
	running     map[string]bool
	paused      bool
	bindHash    string
	bindExpires int64
	bindToken   string
	offset      int64
	offsetToken string
}

func newEngine(s *Store) *Engine { return &Engine{store: s, running: map[string]bool{}} }
func (e *Engine) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			st := e.store.snapshot()
			for _, a := range st.Accounts {
				if a.Enabled && a.Authorized && time.Now().Unix()-a.LastSync >= 60 {
					e.schedule(ctx, a.ID)
				}
			}
			if e.claim("notifications") {
				go func() { defer e.release("notifications"); e.deliver(ctx) }()
			}
			if st.Channels.TelegramEnabled && st.Channels.Token != "" && e.claim("telegram") {
				go func() { defer e.release("telegram"); e.pollTelegram(ctx) }()
			}
		}
	}
}
func (e *Engine) claim(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.paused || e.running[id] {
		return false
	}
	if id != "notifications" && id != "telegram" {
		n := 0
		for k := range e.running {
			if k != "notifications" && k != "telegram" {
				n++
			}
		}
		if n >= 3 {
			return false
		}
	}
	e.running[id] = true
	return true
}
func (e *Engine) release(id string) { e.mu.Lock(); delete(e.running, id); e.mu.Unlock() }
func (e *Engine) schedule(ctx context.Context, id string) bool {
	if !e.claim(id) {
		return false
	}
	go func() { defer e.release(id); e.syncAccount(ctx, id) }()
	return true
}
func matches(r Rule, m Message) bool {
	return r.Enabled && (r.AccountID == "" || r.AccountID == m.AccountID) && (r.Sender == "" || strings.Contains(strings.ToLower(m.Sender), strings.ToLower(r.Sender))) && (r.Keyword == "" || strings.Contains(strings.ToLower(m.Subject+" "+m.Preview), strings.ToLower(r.Keyword)))
}
func mergeMessages(st *State, a Account, in []Message, notify bool) {
	indices := map[string]int{}
	for i, m := range st.Messages {
		indices[m.ID] = i
	}
	for _, m := range in {
		m.Subject = truncate(m.Subject, 1000)
		m.From = truncate(m.From, 200)
		m.Sender = truncate(m.Sender, 320)
		m.Preview = truncate(m.Preview, 1000)
		if i, ok := indices[m.ID]; ok {
			m.Read = st.Messages[i].Read
			m.Starred = st.Messages[i].Starred
			st.Messages[i] = m
			continue
		}
		indices[m.ID] = len(st.Messages)
		st.Messages = append(st.Messages, m)
		if !notify {
			continue
		}
		for _, r := range st.Rules {
			if !matches(r, m) {
				continue
			}
			for _, ch := range []string{"telegram", "webhook"} {
				if (ch == "telegram" && r.Telegram) || (ch == "webhook" && r.Webhook) {
					st.Jobs = append(st.Jobs, Job{ID: randomID(), MessageID: m.ID, RuleID: r.ID, Channel: ch, Mode: r.Mode, Next: time.Now().Unix()})
				}
			}
		}
	}
	sort.SliceStable(st.Messages, func(i, j int) bool { return st.Messages[i].Date < st.Messages[j].Date })
}
func (e *Engine) syncAccount(ctx context.Context, id string) {
	a, ok := findAccount(e.store.snapshot(), id)
	if !ok || !a.Enabled {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	secret, err := e.store.decrypt(a.Secret)
	var messages []Message
	next := a
	updatedSecret := ""
	if err == nil {
		if a.Provider == "outlook" {
			var tok msTokens
			tok, err = refreshMS(ctx, a, secret)
			if err == nil {
				b, _ := json.Marshal(tok)
				updatedSecret = string(b)
				messages, next, err = graphHeaders(ctx, a, tok.Access)
			}
		} else {
			messages, next, err = imapHeaders(ctx, a, secret)
		}
	}
	_ = e.store.update(func(st *State) error {
		for i, current := range st.Accounts {
			if current.ID != id || current.Generation != a.Generation {
				continue
			}
			if err != nil {
				st.Accounts[i].LastSync = time.Now().Unix()
				st.Accounts[i].LastError = err.Error()
				event(st, "error", current.Name+"：同步未完成")
				return nil
			}
			next.LastSync = time.Now().Unix()
			next.LastError = ""
			if updatedSecret != "" {
				next.Secret = e.store.encrypt(updatedSecret)
			}
			st.Accounts[i] = next
			mergeMessages(st, next, messages, a.Initialized && (a.Provider == "outlook" || a.UIDValidity == next.UIDValidity))
			event(st, "sync", current.Name+"：同步完成")
			break
		}
		return nil
	})
}
func (e *Engine) detail(ctx context.Context, m Message) (fetchedMail, error) {
	a, ok := findAccount(e.store.snapshot(), m.AccountID)
	if !ok {
		return fetchedMail{}, errors.New("邮箱已移除")
	}
	secret, err := e.store.decrypt(a.Secret)
	if err != nil {
		return fetchedMail{}, errors.New("凭据不可读取")
	}
	if a.Provider != "outlook" {
		return imapDetail(ctx, a, secret, m)
	}
	tok, err := refreshMS(ctx, a, secret)
	if err != nil {
		return fetchedMail{}, err
	}
	b, _ := json.Marshal(tok)
	if err = e.store.update(func(st *State) error {
		for i, v := range st.Accounts {
			if v.ID == a.ID && v.Generation == a.Generation {
				st.Accounts[i].Secret = e.store.encrypt(string(b))
			}
		}
		return nil
	}); err != nil {
		return fetchedMail{}, errors.New("授权保存失败")
	}
	return graphDetail(ctx, tok.Access, m)
}
func telegramCall(ctx context.Context, token, method string, body any, out any) error {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+token+"/"+method, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := externalHTTP.Do(req)
	if err != nil {
		return errors.New("Telegram网络请求失败")
	}
	defer resp.Body.Close()
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&envelope) != nil || !envelope.OK {
		return errors.New("Telegram拒绝请求，请检查Token、绑定状态或机器人是否被屏蔽")
	}
	if out != nil {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}
func webhookURL(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || len(raw) > 2000 {
		return errors.New("请填写有效的HTTP或HTTPS回调地址")
	}
	return nil
}

var webhookHTTP = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }, Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast() || ip.IP.IsUnspecified() || ip.IP.IsMulticast() {
			return nil, errors.New("unsafe webhook address")
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("empty DNS response")
	}
	return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}}}

func sendWebhook(ctx context.Context, ch Channels, secret string, payload any, id string) error {
	if err := webhookURL(ch.WebhookURL); err != nil {
		return err
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", ch.WebhookURL, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", id)
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("X-Mail-Harbor-Timestamp", stamp)
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(stamp + "."))
		mac.Write(b)
		req.Header.Set("X-Mail-Harbor-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := webhookHTTP.Do(req)
	if err != nil {
		return errors.New("回调请求失败，请检查地址和部署网络")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("回调接口返回HTTP %d", resp.StatusCode)
	}
	return nil
}
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
func (e *Engine) deliver(ctx context.Context) {
	st := e.store.snapshot()
	sent := 0
	for _, job := range st.Jobs {
		if job.Done || job.Next > time.Now().Unix() || job.Attempts >= 8 {
			continue
		}
		if sent >= 10 {
			return
		}
		sent++
		m, ok := findMessage(st, job.MessageID)
		var err error
		if !ok {
			err = errors.New("邮件索引已过缓存期限")
		} else {
			title := "你收到一封新邮件"
			body := ""
			if job.Mode != "notice" {
				title = m.Subject
				body = m.Preview
			}
			if job.Mode == "body" || job.Mode == "summary" {
				var mail fetchedMail
				mail, err = e.detail(ctx, m)
				if err == nil {
					body = mail.Text
				}
			}
			if job.Mode == "summary" {
				body = truncate(body, 350)
			}
			if job.Mode == "notice" {
				body = "新邮件已到达，请打开邮屿查看。"
			}
			a, _ := findAccount(st, m.AccountID)
			payload := map[string]any{"event": "mail.received", "deliveryId": job.ID, "account": a.Name, "mode": job.Mode, "receivedAt": m.Date}
			if job.Mode != "notice" {
				payload["subject"] = m.Subject
				payload["from"] = m.Sender
				payload["body"] = truncate(body, 12000)
			}
			if err == nil {
				if job.Channel == "telegram" {
					if !st.Channels.TelegramEnabled || st.Channels.ChatID == 0 {
						err = errors.New("机器人尚未启用或绑定")
					} else {
						token, _ := e.store.decrypt(st.Channels.Token)
						text := a.Name + " · " + title
						if job.Mode != "notice" {
							text += "\n" + m.Sender
						}
						text += "\n\n" + body
						err = telegramCall(ctx, token, "sendMessage", map[string]any{"chat_id": st.Channels.ChatID, "text": truncate(text, 3500), "link_preview_options": map[string]bool{"is_disabled": true}}, nil)
					}
				} else {
					if !st.Channels.WebhookEnabled {
						err = errors.New("Webhook未启用")
					} else {
						secret, _ := e.store.decrypt(st.Channels.WebhookSecret)
						err = sendWebhook(ctx, st.Channels, secret, payload, job.ID)
					}
				}
			}
		}
		_ = e.store.update(func(next *State) error {
			for i, j := range next.Jobs {
				if j.ID != job.ID {
					continue
				}
				next.Jobs[i].Attempts++
				if err == nil {
					next.Jobs[i].Done = true
					next.Jobs[i].Error = ""
					event(next, "sent", "邮件通知已发送")
				} else {
					next.Jobs[i].Error = err.Error()
					delay := time.Minute * time.Duration(1<<min(j.Attempts, 6))
					next.Jobs[i].Next = time.Now().Add(delay).Unix()
					if next.Jobs[i].Attempts >= 8 {
						event(next, "error", "通知重试次数已达上限，请检查通道后手动重试")
					}
				}
				break
			}
			return nil
		})
	}
}
func (e *Engine) pollTelegram(ctx context.Context) {
	st := e.store.snapshot()
	token, err := e.store.decrypt(st.Channels.Token)
	if err != nil || token == "" {
		return
	}
	e.mu.Lock()
	if e.offsetToken != st.Channels.Token {
		e.offset = 0
		e.offsetToken = st.Channels.Token
	}
	offset := e.offset
	e.mu.Unlock()
	var updates []struct {
		ID      int64 `json:"update_id"`
		Message struct {
			Text string `json:"text"`
			Chat struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
			} `json:"chat"`
		} `json:"message"`
	}
	if telegramCall(ctx, token, "getUpdates", map[string]any{"offset": offset, "timeout": 0, "allowed_updates": []string{"message"}}, &updates) != nil {
		return
	}
	if e.store.snapshot().Channels.Token != st.Channels.Token {
		return
	}
	for _, u := range updates {
		e.mu.Lock()
		e.offset = u.ID + 1
		e.mu.Unlock()
		if u.Message.Chat.Type != "private" {
			continue
		}
		text := strings.TrimSpace(u.Message.Text)
		parts := strings.Fields(text)
		if len(parts) == 2 && parts[0] == "/bind" {
			sum := sha256.Sum256([]byte(parts[1]))
			e.mu.Lock()
			valid := e.bindHash != "" && hmac.Equal([]byte(e.bindHash), []byte(hex.EncodeToString(sum[:]))) && e.bindExpires > time.Now().Unix() && e.bindToken == st.Channels.Token
			if valid {
				e.bindHash = ""
			}
			e.mu.Unlock()
			if valid {
				err = e.store.update(func(next *State) error {
					if next.Channels.Token != st.Channels.Token {
						return errors.New("配置已改变")
					}
					next.Channels.ChatID = u.Message.Chat.ID
					event(next, "bind", "Telegram管理员已绑定")
					return nil
				})
				if err == nil {
					_ = telegramCall(ctx, token, "sendMessage", map[string]any{"chat_id": u.Message.Chat.ID, "text": "绑定成功。新邮件将按你设置的规则推送。"}, nil)
				}
			}
		} else if (text == "/start" || text == "/help") && u.Message.Chat.ID == st.Channels.ChatID {
			_ = telegramCall(ctx, token, "sendMessage", map[string]any{"chat_id": u.Message.Chat.ID, "text": "邮屿邮件通知\n/help 查看说明\n/status 查看连接状态\n通知内容和规则请在网页后台管理。"}, nil)
		} else if text == "/status" && u.Message.Chat.ID == st.Channels.ChatID {
			_ = telegramCall(ctx, token, "sendMessage", map[string]any{"chat_id": u.Message.Chat.ID, "text": fmt.Sprintf("邮屿运行中，已接入%d个邮箱。", len(st.Accounts))}, nil)
		}
	}
}
