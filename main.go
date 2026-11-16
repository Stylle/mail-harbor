package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

//go:embed all:web
var webFS embed.FS

type session struct {
	CSRF  string
	Until int64
}
type deviceGrant struct {
	AccountID, Generation, Code, ClientID, Session string
	Until, Next                                    int64
	Interval                                       int
}
type loginLimit struct {
	Count int
	Start int64
}
type App struct {
	store    *Store
	engine   *Engine
	mu       sync.Mutex
	sessions map[string]session
	limits   map[string]loginLimit
	grants   map[string]deviceGrant
}

func main() {
	dir := os.Getenv("DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	s, err := openStore(dir)
	if err != nil {
		log.Fatal("Cannot open private data directory: ", err)
	}
	defer s.db.Close()
	if initial := os.Getenv("PASSWORD"); s.snapshot().Password == "" && initial != "" {
		if len(initial) < 12 || len(initial) > 256 {
			log.Fatal("Initial PASSWORD must contain 12 to 256 characters")
		}
		name := os.Getenv("USER")
		if name == "" {
			name = "admin"
		}
		if len(name) > 64 {
			log.Fatal("Initial USER is too long")
		}
		if err = s.update(func(st *State) error {
			st.Username = name
			st.Password = passwordHash(initial)
			event(st, "setup", "管理账户已创建")
			return nil
		}); err != nil {
			log.Fatal("Cannot initialize administrator")
		}
	}
	app := &App{store: s, engine: newEngine(s), sessions: map[string]session{}, limits: map[string]loginLimit{}, grants: map[string]deviceGrant{}}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go app.engine.run(ctx)
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:28187"
	}
	srv := &http.Server{Addr: addr, Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 130 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("Mail Harbor %s listening on %s", version, addr)
	if err = srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal("HTTP server stopped")
	}
}
func jsonOut(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func fail(w http.ResponseWriter, status int, text string) {
	jsonOut(w, status, map[string]string{"error": text})
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "请求需要JSON格式")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		fail(w, 400, "请求内容无效或超过大小限制")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		fail(w, 400, "请求只能包含一个JSON对象")
		return false
	}
	return true
}
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	u, e := url.Parse(origin)
	return e == nil && u.Host == r.Host && (u.Scheme == "https" || u.Scheme == "http")
}
func sessionKey(token string) string {
	b := sha256.Sum256([]byte(token))
	return hex.EncodeToString(b[:])
}
func (a *App) auth(r *http.Request) (session, string, bool) {
	cookie, e := r.Cookie("mail_harbor")
	if e != nil {
		return session{}, "", false
	}
	key := sessionKey(cookie.Value)
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[key]
	return s, key, ok && s.Until > time.Now().Unix()
}
func (a *App) clearSessions() {
	a.mu.Lock()
	a.sessions = map[string]session{}
	a.grants = map[string]deviceGrant{}
	a.mu.Unlock()
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		jsonOut(w, 200, map[string]any{"ok": true, "version": version})
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.NotFound(w, r)
			return
		}
		files, _ := fs.Sub(webFS, "web")
		if r.URL.Path != "/" {
			if _, e := fs.Stat(files, strings.TrimPrefix(r.URL.Path, "/")); e != nil {
				http.NotFound(w, r)
				return
			}
		}
		http.FileServer(http.FS(files)).ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !sameOrigin(r) {
		fail(w, 403, "请求来源不匹配")
		return
	}
	if r.URL.Path == "/api/session" && r.Method == "GET" {
		s, _, ok := a.auth(r)
		st := a.store.snapshot()
		data := map[string]any{"configured": st.Password != "", "authenticated": ok, "version": version}
		if ok {
			data["csrf"] = s.CSRF
			data["username"] = st.Username
		}
		jsonOut(w, 200, data)
		return
	}
	if r.URL.Path == "/api/login" && r.Method == "POST" {
		a.login(w, r, false)
		return
	}
	if r.URL.Path == "/api/setup" && r.Method == "POST" {
		a.login(w, r, true)
		return
	}
	s, key, ok := a.auth(r)
	if !ok {
		fail(w, 401, "请登录后继续")
		return
	}
	if r.Method != "GET" {
		csrf := r.Header.Get("X-CSRF-Token")
		if subtle.ConstantTimeCompare([]byte(csrf), []byte(s.CSRF)) != 1 {
			fail(w, 403, "页面校验已失效，请刷新后重试")
			return
		}
		a.engine.mu.Lock()
		restoring := a.engine.paused
		a.engine.mu.Unlock()
		if restoring {
			fail(w, 409, "系统正在恢复备份，请稍后再试")
			return
		}
	}
	switch r.Method + " " + r.URL.Path {
	case "POST /api/logout":
		a.mu.Lock()
		delete(a.sessions, key)
		a.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "mail_harbor", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		jsonOut(w, 200, map[string]bool{"ok": true})
	case "GET /api/state":
		a.publicState(w)
	case "POST /api/account":
		a.saveAccount(w, r)
	case "POST /api/account/test":
		a.testAccount(w, r)
	case "POST /api/account/delete":
		a.deleteAccount(w, r)
	case "POST /api/sync":
		var v struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &v) {
			return
		}
		if _, ok := findAccount(a.store.snapshot(), v.ID); !ok {
			fail(w, 404, "邮箱不存在")
			return
		}
		if !a.engine.schedule(context.Background(), v.ID) {
			fail(w, 409, "同步正在进行或系统正在恢复，请稍后再试")
			return
		}
		jsonOut(w, 202, map[string]bool{"ok": true})
	case "GET /api/message":
		a.messageDetail(w, r)
	case "GET /api/attachment":
		a.attachment(w, r)
	case "POST /api/message/flags":
		a.flags(w, r)
	case "POST /api/channels":
		a.saveChannels(w, r)
	case "POST /api/webhook/test":
		a.testWebhook(w, r)
	case "POST /api/telegram/bind":
		a.bind(w, r)
	case "POST /api/telegram/unbind":
		a.engine.mu.Lock()
		a.engine.bindHash = ""
		a.engine.mu.Unlock()
		a.mutate(w, func(st *State) error { st.Channels.ChatID = 0; return nil })
	case "POST /api/rules":
		a.rules(w, r)
	case "POST /api/jobs/retry":
		a.mutate(w, func(st *State) error {
			for i, j := range st.Jobs {
				if !j.Done {
					st.Jobs[i].Attempts = 0
					st.Jobs[i].Next = time.Now().Unix()
				}
			}
			return nil
		})
	case "POST /api/security":
		a.security(w, r)
	case "POST /api/backup":
		a.backup(w, r, false)
	case "POST /api/restore":
		a.backup(w, r, true)
	case "POST /api/outlook/start":
		a.startOutlook(w, r, key)
	case "POST /api/outlook/poll":
		a.pollOutlook(w, r, key)
	default:
		fail(w, 404, "接口不存在")
	}
}
func (a *App) login(w http.ResponseWriter, r *http.Request, setup bool) {
	var v struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.Username) > 64 || len(v.Password) > 256 {
		fail(w, 400, "账号或密码长度超出限制")
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now().Unix()
	a.mu.Lock()
	limit := a.limits[ip]
	if now-limit.Start > 600 {
		limit = loginLimit{Start: now}
	}
	if limit.Count >= 10 {
		a.mu.Unlock()
		fail(w, 429, "尝试次数过多，请10分钟后重试")
		return
	}
	limit.Count++
	if len(a.limits) > 2000 {
		for k, l := range a.limits {
			if now-l.Start > 600 {
				delete(a.limits, k)
			}
		}
	}
	a.limits[ip] = limit
	a.mu.Unlock()
	st := a.store.snapshot()
	if setup {
		if st.Password != "" {
			fail(w, 409, "管理账户已创建")
			return
		}
		if len(v.Password) < 12 || len(v.Password) > 256 || len(v.Username) < 1 || len(v.Username) > 64 {
			fail(w, 400, "用户名1～64个字符，密码至少12个字符")
			return
		}
		hash := passwordHash(v.Password)
		if err := a.store.update(func(st *State) error {
			if st.Password != "" {
				return errors.New("管理账户已创建")
			}
			st.Username = v.Username
			st.Password = hash
			event(st, "setup", "管理账户已创建")
			return nil
		}); err != nil {
			fail(w, 409, "账户创建失败，请刷新重试")
			return
		}
		st.Password = hash
	} else if st.Password == "" || v.Username != st.Username || !passwordOK(st.Password, v.Password) {
		fail(w, 401, "账号或密码不正确")
		return
	}
	token := randomID()
	s := session{CSRF: randomID(), Until: now + 7*86400}
	a.mu.Lock()
	if a.store.snapshot().Password != st.Password {
		a.mu.Unlock()
		fail(w, 401, "管理账户已改变，请重新登录")
		return
	}
	for k, old := range a.sessions {
		if old.Until < now {
			delete(a.sessions, k)
		}
	}
	if len(a.sessions) > 100 {
		a.sessions = map[string]session{}
	}
	a.sessions[sessionKey(token)] = s
	delete(a.limits, ip)
	a.mu.Unlock()
	secure := r.TLS != nil || (os.Getenv("TRUST_PROXY") == "1" && r.Header.Get("X-Forwarded-Proto") == "https")
	http.SetCookie(w, &http.Cookie{Name: "mail_harbor", Value: token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 86400})
	jsonOut(w, 200, map[string]any{"csrf": s.CSRF, "username": v.Username})
}
func (a *App) publicState(w http.ResponseWriter) {
	st := a.store.snapshot()
	if st.Messages == nil {
		st.Messages = []Message{}
	}
	if st.Rules == nil {
		st.Rules = []Rule{}
	}
	if st.Events == nil {
		st.Events = []Event{}
	}
	accounts := []map[string]any{}
	for _, v := range st.Accounts {
		accounts = append(accounts, map[string]any{"id": v.ID, "name": v.Name, "email": v.Email, "provider": v.Provider, "enabled": v.Enabled, "clientId": v.ClientID, "authorized": v.Authorized, "hasSecret": v.Secret != "", "initialized": v.Initialized, "lastSync": v.LastSync, "lastError": v.LastError})
	}
	ch := map[string]any{"telegramEnabled": st.Channels.TelegramEnabled, "hasToken": st.Channels.Token != "", "chatId": st.Channels.ChatID, "botName": st.Channels.BotName, "webhookEnabled": st.Channels.WebhookEnabled, "webhookUrl": st.Channels.WebhookURL, "hasWebhookSecret": st.Channels.WebhookSecret != ""}
	jobs := map[string]int{"pending": 0, "failed": 0, "sent": 0}
	for _, j := range st.Jobs {
		if j.Done {
			jobs["sent"]++
		} else if j.Attempts >= 8 {
			jobs["failed"]++
		} else {
			jobs["pending"]++
		}
	}
	a.engine.mu.Lock()
	busy := []string{}
	for k := range a.engine.running {
		busy = append(busy, k)
	}
	a.engine.mu.Unlock()
	messages := st.Messages
	sort.SliceStable(messages, func(i, j int) bool { return messages[i].Date > messages[j].Date })
	jsonOut(w, 200, map[string]any{"accounts": accounts, "messages": messages, "channels": ch, "rules": st.Rules, "events": st.Events, "jobs": jobs, "busy": busy})
}

type accountDraft struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
	Password string `json:"password"`
	ClientID string `json:"clientId"`
}

func (a *App) draft(v accountDraft) (Account, string, error) {
	acc := Account{ID: v.ID, Name: strings.TrimSpace(v.Name), Provider: v.Provider, Email: strings.TrimSpace(v.Email), Enabled: v.Enabled, ClientID: strings.TrimSpace(v.ClientID), Generation: randomID()}
	if old, ok := findAccount(a.store.snapshot(), v.ID); ok {
		if old.Provider != v.Provider || !strings.EqualFold(old.Email, acc.Email) {
			return acc, "", errors.New("已接入邮箱的地址和提供商不可变更，请新增邮箱")
		}
		acc = old
		acc.Name = strings.TrimSpace(v.Name)
		acc.Enabled = v.Enabled
		acc.Generation = randomID()
		if acc.ClientID != v.ClientID {
			acc.Secret = ""
			acc.Authorized = false
			acc.Cursor = ""
			acc.Initialized = false
		}
		acc.ClientID = strings.TrimSpace(v.ClientID)
	} else {
		acc.ID = randomID()
	}
	if _, ok := providerHosts[acc.Provider]; !ok && acc.Provider != "outlook" {
		return acc, "", errors.New("请选择支持的邮箱提供商")
	}
	address, e := mail.ParseAddress(acc.Email)
	if e != nil || address.Address != acc.Email || len(acc.Name) < 1 || len(acc.Name) > 60 {
		return acc, "", errors.New("请填写有效邮箱地址和名称（最多60个字符）")
	}
	if acc.Provider == "outlook" {
		if !regexp.MustCompile(`^[0-9a-fA-F-]{36}$`).MatchString(acc.ClientID) {
			return acc, "", errors.New("请填写微软应用的Application Client ID")
		}
		return acc, "", nil
	}
	secret := v.Password
	if acc.Provider == "gmail" {
		secret = strings.Join(strings.Fields(secret), "")
	}
	if secret == "" && acc.Secret != "" {
		secret, e = a.store.decrypt(acc.Secret)
	}
	if e != nil || len(secret) < 6 || len(secret) > 512 {
		return acc, "", errors.New("请填写客户端授权码或应用专用密码")
	}
	return acc, secret, nil
}
func (a *App) saveAccount(w http.ResponseWriter, r *http.Request) {
	var v accountDraft
	if !decode(w, r, &v) {
		return
	}
	acc, secret, err := a.draft(v)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if acc.Provider != "outlook" {
		acc.Secret = a.store.encrypt(strings.TrimSpace(secret))
		acc.Authorized = true
	}
	err = a.store.update(func(st *State) error {
		for i, old := range st.Accounts {
			if old.ID == acc.ID {
				// Preserve checkpoints and refreshed OAuth credentials committed since the form opened.
				if old.ClientID == acc.ClientID {
					acc.Cursor = old.Cursor
					acc.LastUID = old.LastUID
					acc.UIDValidity = old.UIDValidity
					acc.Initialized = old.Initialized
					acc.LastSync = old.LastSync
					acc.LastError = old.LastError
					if acc.Provider == "outlook" {
						acc.Secret = old.Secret
						acc.Authorized = old.Authorized
					}
				}
				st.Accounts[i] = acc
				return nil
			}
		}
		if len(st.Accounts) >= 20 {
			return errors.New("最多接入20个邮箱")
		}
		st.Accounts = append(st.Accounts, acc)
		event(st, "account", "邮箱配置已保存")
		return nil
	})
	if err != nil {
		fail(w, 400, "保存失败：邮箱数量已达上限或磁盘不可写")
		return
	}
	jsonOut(w, 200, map[string]any{"id": acc.ID, "ok": true})
}
func (a *App) testAccount(w http.ResponseWriter, r *http.Request) {
	var v accountDraft
	if !decode(w, r, &v) {
		return
	}
	acc, secret, err := a.draft(v)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if acc.Provider == "outlook" {
		fail(w, 400, "Outlook请先保存应用ID，再完成微软授权")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	c, err := imapConnect(ctx, acc, strings.TrimSpace(secret))
	if err == nil {
		_, err = c.Select("INBOX", true)
		c.Terminate()
	}
	if err != nil {
		fail(w, 400, "连接失败，请核对当前表单、邮箱IMAP开关及部署网络")
		return
	}
	jsonOut(w, 200, map[string]any{"ok": true, "message": "连接成功，当前表单未保存"})
}
func (a *App) mutate(w http.ResponseWriter, fn func(*State) error) {
	if err := a.store.update(fn); err != nil {
		fail(w, 400, "操作失败，请稍后重试")
		return
	}
	jsonOut(w, 200, map[string]bool{"ok": true})
}
func (a *App) deleteAccount(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mutate(w, func(st *State) error {
		acc := []Account{}
		for _, a := range st.Accounts {
			if a.ID != v.ID {
				acc = append(acc, a)
			}
		}
		st.Accounts = acc
		msgs := []Message{}
		for _, m := range st.Messages {
			if m.AccountID != v.ID {
				msgs = append(msgs, m)
			}
		}
		st.Messages = msgs
		for i, j := range st.Jobs {
			if _, ok := findMessage(*st, j.MessageID); !ok {
				st.Jobs[i].Done = true
			}
		}
		rules := []Rule{}
		for _, rule := range st.Rules {
			if rule.AccountID != v.ID {
				rules = append(rules, rule)
			}
		}
		st.Rules = rules
		event(st, "account", "邮箱已断开，本地索引已移除，原邮箱未修改")
		return nil
	})
}
func (a *App) messageDetail(w http.ResponseWriter, r *http.Request) {
	m, ok := findMessage(a.store.snapshot(), r.URL.Query().Get("id"))
	if !ok {
		fail(w, 404, "邮件不在缓存索引中")
		return
	}
	detail, err := a.engine.detail(r.Context(), m)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	jsonOut(w, 200, detail.Detail)
}
func (a *App) attachment(w http.ResponseWriter, r *http.Request) {
	m, ok := findMessage(a.store.snapshot(), r.URL.Query().Get("id"))
	index, err := strconv.Atoi(r.URL.Query().Get("part"))
	if !ok || err != nil {
		fail(w, 404, "附件不存在")
		return
	}
	detail, err := a.engine.detail(r.Context(), m)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	for _, att := range detail.Attachments {
		if att.Index == index {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": att.Name}))
			w.Header().Set("Content-Length", strconv.Itoa(len(detail.files[index])))
			_, _ = w.Write(detail.files[index])
			return
		}
	}
	fail(w, 404, "附件不存在")
}
func (a *App) flags(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID      string `json:"id"`
		Read    *bool  `json:"read"`
		Starred *bool  `json:"starred"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mutate(w, func(st *State) error {
		for i, m := range st.Messages {
			if m.ID == v.ID {
				if v.Read != nil {
					st.Messages[i].Read = *v.Read
				}
				if v.Starred != nil {
					st.Messages[i].Starred = *v.Starred
				}
				return nil
			}
		}
		return errors.New("missing")
	})
}

type channelDraft struct {
	TelegramEnabled    bool   `json:"telegramEnabled"`
	Token              string `json:"token"`
	ClearToken         bool   `json:"clearToken"`
	WebhookEnabled     bool   `json:"webhookEnabled"`
	WebhookURL         string `json:"webhookUrl"`
	WebhookSecret      string `json:"webhookSecret"`
	ClearWebhookSecret bool   `json:"clearWebhookSecret"`
}

func (a *App) channels(v channelDraft) (Channels, error) {
	ch := a.store.snapshot().Channels
	ch.TelegramEnabled = v.TelegramEnabled
	ch.WebhookEnabled = v.WebhookEnabled
	ch.WebhookURL = strings.TrimSpace(v.WebhookURL)
	if v.Token != "" {
		if !regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$`).MatchString(v.Token) {
			return ch, errors.New("Telegram Token格式不正确")
		}
		plain, _ := a.store.decrypt(ch.Token)
		if plain != v.Token {
			ch.Token = a.store.encrypt(v.Token)
			ch.ChatID = 0
			ch.BotName = ""
		}
	}
	if v.ClearToken {
		ch.Token = ""
		ch.ChatID = 0
		ch.BotName = ""
		ch.TelegramEnabled = false
	}
	if v.WebhookSecret != "" {
		if len(v.WebhookSecret) > 512 {
			return ch, errors.New("签名密钥过长")
		}
		ch.WebhookSecret = a.store.encrypt(v.WebhookSecret)
	}
	if v.ClearWebhookSecret {
		ch.WebhookSecret = ""
	}
	if ch.WebhookEnabled {
		if err := webhookURL(ch.WebhookURL); err != nil {
			return ch, err
		}
	}
	if ch.TelegramEnabled && ch.Token == "" {
		return ch, errors.New("请填写机器人Token")
	}
	return ch, nil
}
func (a *App) saveChannels(w http.ResponseWriter, r *http.Request) {
	var v channelDraft
	if !decode(w, r, &v) {
		return
	}
	ch, err := a.channels(v)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if ch.TelegramEnabled {
		token, _ := a.store.decrypt(ch.Token)
		var me struct {
			Username string `json:"username"`
		}
		if err = telegramCall(r.Context(), token, "getMe", map[string]any{}, &me); err != nil {
			fail(w, 400, err.Error())
			return
		}
		var info struct {
			URL string `json:"url"`
		}
		if err = telegramCall(r.Context(), token, "getWebhookInfo", map[string]any{}, &info); err != nil || info.URL != "" {
			fail(w, 400, "机器人正在使用Webhook或无法确认状态，请使用专用机器人并在原服务关闭Webhook")
			return
		}
		ch.BotName = me.Username
		err = telegramCall(r.Context(), token, "setMyCommands", map[string]any{"commands": []map[string]string{{"command": "help", "description": "使用说明"}, {"command": "status", "description": "查看连接状态"}}}, nil)
		if err != nil {
			fail(w, 400, "机器人菜单创建失败，请稍后重新保存")
			return
		}
	}
	a.mutate(w, func(st *State) error {
		if st.Channels.Token != ch.Token {
			a.engine.mu.Lock()
			a.engine.bindHash = ""
			a.engine.mu.Unlock()
		}
		st.Channels = ch
		event(st, "settings", "通知通道已保存")
		return nil
	})
}
func (a *App) testWebhook(w http.ResponseWriter, r *http.Request) {
	var v channelDraft
	if !decode(w, r, &v) {
		return
	}
	ch, err := a.channels(v)
	if err == nil {
		err = webhookURL(ch.WebhookURL)
	}
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	secret, _ := a.store.decrypt(ch.WebhookSecret)
	err = sendWebhook(r.Context(), ch, secret, map[string]any{"event": "mail.test", "message": "邮屿Webhook连接测试，不包含邮件内容"}, randomID())
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	jsonOut(w, 200, map[string]any{"ok": true, "message": "测试成功，当前表单未保存"})
}
func (a *App) bind(w http.ResponseWriter, r *http.Request) {
	ch := a.store.snapshot().Channels
	if !ch.TelegramEnabled || ch.Token == "" {
		fail(w, 400, "请先填写Token并保存设置")
		return
	}
	code := randomID()[:12]
	sum := sha256.Sum256([]byte(code))
	a.engine.mu.Lock()
	a.engine.bindHash = hex.EncodeToString(sum[:])
	a.engine.bindExpires = time.Now().Unix() + 300
	a.engine.bindToken = ch.Token
	a.engine.mu.Unlock()
	jsonOut(w, 200, map[string]any{"command": "/bind " + code, "expires": time.Now().Unix() + 300, "botName": ch.BotName})
}
func (a *App) rules(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Rules []Rule `json:"rules"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.Rules) > 50 {
		fail(w, 400, "规则最多50条")
		return
	}
	if v.Rules == nil {
		v.Rules = []Rule{}
	}
	ids := map[string]bool{}
	for i, rule := range v.Rules {
		if rule.ID == "" {
			rule.ID = randomID()
		}
		if ids[rule.ID] || len(rule.Name) < 1 || len(rule.Name) > 80 || len(rule.Keyword) > 200 || len(rule.Sender) > 200 || (rule.Mode != "notice" && rule.Mode != "summary" && rule.Mode != "body") || (!rule.Telegram && !rule.Webhook) {
			fail(w, 400, "请填写完整规则并至少选择一个通知通道")
			return
		}
		if rule.AccountID != "" {
			if _, ok := findAccount(a.store.snapshot(), rule.AccountID); !ok {
				fail(w, 400, "规则引用的邮箱不存在")
				return
			}
		}
		ids[rule.ID] = true
		v.Rules[i] = rule
	}
	a.mutate(w, func(st *State) error { st.Rules = v.Rules; return nil })
}
func (a *App) security(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Current  string `json:"current"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	st := a.store.snapshot()
	if !passwordOK(st.Password, v.Current) {
		fail(w, 400, "当前密码不正确")
		return
	}
	if len(v.Password) < 12 || len(v.Password) > 256 || len(v.Username) < 1 || len(v.Username) > 64 {
		fail(w, 400, "用户名1～64个字符，新密码至少12个字符")
		return
	}
	hash := passwordHash(v.Password)
	if err := a.store.update(func(next *State) error {
		if next.Password != st.Password {
			return errors.New("account changed")
		}
		next.Username = v.Username
		next.Password = hash
		event(next, "security", "管理密码已修改")
		return nil
	}); err != nil {
		fail(w, 409, "账户已改变，请重新登录")
		return
	}
	a.clearSessions()
	jsonOut(w, 200, map[string]bool{"ok": true})
}

func (a *App) startOutlook(w http.ResponseWriter, r *http.Request, key string) {
	var v struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &v) {
		return
	}
	acc, ok := findAccount(a.store.snapshot(), v.ID)
	if !ok || acc.Provider != "outlook" {
		fail(w, 400, "请先保存Outlook邮箱及Client ID")
		return
	}
	var result struct {
		Code     string `json:"device_code"`
		User     string `json:"user_code"`
		URL      string `json:"verification_uri"`
		Expires  int64  `json:"expires_in"`
		Interval int    `json:"interval"`
		Error    string `json:"error"`
	}
	err := formJSON(r.Context(), msBase+"devicecode", url.Values{"client_id": {acc.ClientID}, "scope": {"offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read"}}, &result)
	if err != nil || result.Code == "" || result.Error != "" {
		fail(w, 400, "微软授权初始化失败，请检查Client ID、个人账号支持和公共客户端流开关")
		return
	}
	id := randomID()
	a.mu.Lock()
	for k, g := range a.grants {
		if g.Until < time.Now().Unix() || g.AccountID == acc.ID {
			delete(a.grants, k)
		}
	}
	a.grants[id] = deviceGrant{AccountID: acc.ID, Generation: acc.Generation, Code: result.Code, ClientID: acc.ClientID, Session: key, Until: time.Now().Unix() + result.Expires, Interval: max(5, result.Interval), Next: time.Now().Unix() + int64(max(5, result.Interval))}
	a.mu.Unlock()
	jsonOut(w, 200, map[string]any{"id": id, "code": result.User, "url": result.URL, "interval": max(5, result.Interval), "expires": result.Expires})
}
func (a *App) pollOutlook(w http.ResponseWriter, r *http.Request, key string) {
	var v struct {
		ID string `json:"id"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mu.Lock()
	g, ok := a.grants[v.ID]
	if !ok || g.Session != key || g.Until < time.Now().Unix() {
		a.mu.Unlock()
		fail(w, 400, "授权已过期，请重新生成")
		return
	}
	if g.Next > time.Now().Unix() {
		a.mu.Unlock()
		jsonOut(w, 200, map[string]string{"status": "pending"})
		return
	}
	g.Next = time.Now().Unix() + int64(g.Interval)
	a.grants[v.ID] = g
	a.mu.Unlock()
	var tok msTokens
	err := formJSON(r.Context(), msBase+"token", url.Values{"client_id": {g.ClientID}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {g.Code}}, &tok)
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	if tok.Error == "authorization_pending" || tok.Error == "slow_down" {
		if tok.Error == "slow_down" {
			a.mu.Lock()
			g.Interval += 5
			g.Next = time.Now().Unix() + int64(g.Interval)
			a.grants[v.ID] = g
			a.mu.Unlock()
		}
		jsonOut(w, 200, map[string]string{"status": "pending"})
		return
	}
	if tok.Access == "" || tok.Refresh == "" {
		fail(w, 400, "授权未完成或被拒绝，请检查应用权限后重试")
		return
	}
	// Verify the authorized Microsoft mailbox matches the account being configured.
	req, _ := http.NewRequestWithContext(r.Context(), "GET", "https://graph.microsoft.com/v1.0/me?$select=mail,userPrincipalName", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Access)
	resp, err := externalHTTP.Do(req)
	if err != nil {
		fail(w, 502, "微软账号校验失败")
		return
	}
	defer resp.Body.Close()
	var who struct {
		Mail string `json:"mail"`
		UPN  string `json:"userPrincipalName"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&who) != nil {
		fail(w, 400, "无法确认微软邮箱身份")
		return
	}
	tok.Until = time.Now().Unix() + tok.Expires
	b, _ := json.Marshal(tok)
	err = a.store.update(func(st *State) error {
		for i, acc := range st.Accounts {
			if acc.ID == g.AccountID && acc.Generation == g.Generation {
				if !strings.EqualFold(acc.Email, who.Mail) && !strings.EqualFold(acc.Email, who.UPN) {
					return errors.New("授权邮箱与填写地址不一致，请使用主要邮箱地址")
				}
				st.Accounts[i].Secret = a.store.encrypt(string(b))
				st.Accounts[i].Authorized = true
				st.Accounts[i].LastSync = 0
				return nil
			}
		}
		return errors.New("邮箱配置已改变，请重新授权")
	})
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.mu.Lock()
	delete(a.grants, v.ID)
	a.mu.Unlock()
	jsonOut(w, 200, map[string]string{"status": "authorized"})
}

var backupMagic = []byte("MHBAK001")

func packBackup(st State, password string) ([]byte, error) {
	data, e := json.Marshal(st)
	if e != nil {
		return nil, e
	}
	if len(data) > 19<<20 {
		return nil, errors.New("backup exceeds portable size limit")
	}
	salt := make([]byte, 16)
	if _, e = rand.Read(salt); e != nil {
		return nil, e
	}
	key := pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
	encrypted, e := seal(key, data)
	if e != nil {
		return nil, e
	}
	return append(append(append([]byte{}, backupMagic...), salt...), encrypted...), nil
}
func unpackBackup(data []byte, password string) (State, error) {
	var st State
	if len(data) < 52 || string(data[:8]) != string(backupMagic) {
		return st, errors.New("不是邮屿备份包")
	}
	key := pbkdf2.Key([]byte(password), data[8:24], 600000, 32, sha256.New)
	plain, e := unseal(key, data[24:])
	if e != nil {
		return st, errors.New("备份密码不正确或备份包已损坏")
	}
	if json.Unmarshal(plain, &st) != nil || validateBackup(st) != nil {
		return st, errors.New("备份结构或版本不受支持")
	}
	return st, nil
}
func validateBackup(st State) error {
	bad := errors.New("invalid backup")
	hash, e := base64.RawStdEncoding.DecodeString(st.Password)
	if e != nil || len(hash) != 48 || st.Version != 1 || len(st.Username) < 1 || len(st.Username) > 64 || len(st.Accounts) > 20 || len(st.Messages) > maxMessages || len(st.Jobs) > 10000 || len(st.Rules) > 50 || len(st.Events) > 150 {
		return bad
	}
	ids := map[string]bool{}
	for _, acc := range st.Accounts {
		if len(acc.ID) < 1 || len(acc.ID) > 100 || ids[acc.ID] || len(acc.Name) > 60 || len(acc.Secret) > 20000 {
			return bad
		}
		if _, e := mail.ParseAddress(acc.Email); e != nil {
			return bad
		}
		if _, ok := providerHosts[acc.Provider]; !ok && acc.Provider != "outlook" {
			return bad
		}
		ids[acc.ID] = true
	}
	mids := map[string]bool{}
	for _, m := range st.Messages {
		if !ids[m.AccountID] || mids[m.ID] || m.ID == "" || len(m.RemoteID) > 2000 || len(m.Subject) > 100000 || len(m.Preview) > 100000 {
			return bad
		}
		mids[m.ID] = true
	}
	if st.Channels.WebhookEnabled && webhookURL(st.Channels.WebhookURL) != nil {
		return bad
	}
	for _, r := range st.Rules {
		if r.AccountID != "" && !ids[r.AccountID] {
			return bad
		}
		if r.Mode != "notice" && r.Mode != "summary" && r.Mode != "body" {
			return bad
		}
	}
	for _, j := range st.Jobs {
		if !j.Done && !mids[j.MessageID] {
			return bad
		}
		if j.Channel != "webhook" && j.Channel != "telegram" {
			return bad
		}
	}
	return nil
}
func (a *App) backup(w http.ResponseWriter, r *http.Request, restore bool) {
	var v struct {
		Password string `json:"password"`
		Data     string `json:"data"`
	}
	if !decode(w, r, &v) {
		return
	}
	if len(v.Password) < 12 || len(v.Password) > 256 {
		fail(w, 400, "备份密码至少12个字符，请妥善保存")
		return
	}
	if !restore {
		st := a.store.snapshot()
		for i, acc := range st.Accounts {
			plain, e := a.store.decrypt(acc.Secret)
			if e != nil {
				fail(w, 500, "凭据读取失败，未生成备份")
				return
			}
			st.Accounts[i].Secret = plain
		}
		var err error
		st.Channels.Token, err = a.store.decrypt(st.Channels.Token)
		if err != nil {
			fail(w, 500, "通道凭据读取失败")
			return
		}
		st.Channels.WebhookSecret, err = a.store.decrypt(st.Channels.WebhookSecret)
		if err != nil {
			fail(w, 500, "通道凭据读取失败")
			return
		}
		data, err := packBackup(st, v.Password)
		if err != nil {
			fail(w, 500, "备份生成失败")
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="mail-harbor-`+time.Now().UTC().Format("20060102-150405")+`.mhbackup"`)
		_, _ = w.Write(data)
		return
	}
	data, err := base64.StdEncoding.DecodeString(v.Data)
	if err != nil || len(data) > 20<<20 {
		fail(w, 400, "备份文件无效或超过20MB")
		return
	}
	st, err := unpackBackup(data, v.Password)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	for i, acc := range st.Accounts {
		st.Accounts[i].Secret = a.store.encrypt(acc.Secret)
		st.Accounts[i].Generation = randomID()
	}
	st.Channels.Token = a.store.encrypt(st.Channels.Token)
	st.Channels.WebhookSecret = a.store.encrypt(st.Channels.WebhookSecret)
	a.engine.mu.Lock()
	if a.engine.paused {
		a.engine.mu.Unlock()
		fail(w, 409, "系统正在恢复")
		return
	}
	a.engine.paused = true
	a.engine.mu.Unlock()
	defer func() { a.engine.mu.Lock(); a.engine.paused = false; a.engine.mu.Unlock() }()
	deadline := time.Now().Add(95 * time.Second)
	for {
		a.engine.mu.Lock()
		busy := len(a.engine.running) > 0
		a.engine.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			fail(w, 409, "后台任务尚未结束，请稍后重新恢复")
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err = a.store.update(func(next *State) error {
		*next = st
		event(next, "restore", "备份恢复完成，旧登录已失效")
		return nil
	}); err != nil {
		fail(w, 500, "恢复失败，原数据仍保留")
		return
	}
	a.clearSessions()
	a.engine.mu.Lock()
	a.engine.bindHash = ""
	a.engine.offset = 0
	a.engine.mu.Unlock()
	jsonOut(w, 200, map[string]bool{"ok": true})
}
