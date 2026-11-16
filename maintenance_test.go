package main

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTOTPAgainstRFC6238Vectors(t *testing.T) {
	key := make([]byte, 20)
	for i := range key {
		key[i] = byte('0' + (i+1)%10)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key)
	for _, v := range []struct {
		stamp int64
		code  string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if totp(secret, v.stamp/30) != v.code {
			t.Fatal("RFC6238 SHA1 vector failed")
		}
	}
}
func TestHTMLAnchorsBecomeSafeReadableLinks(t *testing.T) {
	text := plainHTML(`<p>Read <a href="https://example.org/verify?a=1&amp;b=2">verify account</a>.</p><a href="javascript:alert(1)">bad</a><a href="https://user:secret@example.org">credential URL</a><img src="https://tracking.invalid/pixel">`)
	if !strings.Contains(text, "verify account (https://example.org/verify?a=1&b=2)") {
		t.Fatal("HTML anchor destination lost")
	}
	for _, blocked := range []string{"javascript:", "user:secret", "tracking.invalid"} {
		if strings.Contains(text, blocked) {
			t.Fatal("unsafe HTML destination exposed as link")
		}
	}
}

func TestMandatoryEnrollmentAndLegacyMigration(t *testing.T) {
	a := testApp(t)
	_ = a.store.update(func(st *State) error {
		st.Username = "legacy"
		st.Password = passwordHash("old-local-password")
		return nil
	})
	login := request(t, a, "login", map[string]string{"username": "legacy", "password": "old-local-password"}, nil, "")
	if login.Code != 200 {
		t.Fatal("legacy password rejected before upgrade")
	}
	var auth struct {
		CSRF          string `json:"csrf"`
		Authenticated bool   `json:"authenticated"`
		Setup         bool   `json:"needsTwoFactorSetup"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &auth)
	if auth.Authenticated || !auth.Setup {
		t.Fatal("legacy account bypassed required enrollment")
	}
	cookie := login.Result().Cookies()[0]
	if request(t, a, "state", nil, cookie, "").Code != 403 || request(t, a, "send", map[string]string{}, cookie, auth.CSRF).Code != 403 {
		t.Fatal("restricted session accessed mail")
	}
	begin := request(t, a, "2fa/begin", map[string]string{}, cookie, auth.CSRF)
	var pending struct {
		Secret string `json:"secret"`
		QR     []byte `json:"qr"`
	}
	_ = json.Unmarshal(begin.Body.Bytes(), &pending)
	if len(pending.QR) < 100 {
		t.Fatal("no local enrollment QR")
	}
	code := totp(pending.Secret, time.Now().Unix()/30)
	if request(t, a, "2fa/confirm", map[string]string{"code": code, "password": "Still-weak"}, cookie, auth.CSRF).Code != 400 {
		t.Fatal("weak upgrade password accepted")
	}
	confirm := request(t, a, "2fa/confirm", map[string]string{"code": code, "password": "Upgraded-Password9!"}, cookie, auth.CSRF)
	if confirm.Code != 200 {
		t.Fatal("migration failed")
	}
	if request(t, a, "state", nil, cookie, "").Code != 401 {
		t.Fatal("pre-enrollment cookie survived")
	}
	if request(t, a, "state", nil, confirm.Result().Cookies()[0], "").Code != 200 {
		t.Fatal("full enrollment not usable")
	}
	st := a.store.snapshot()
	if st.PasswordPolicy != 1 || !passwordOK(st.Password, "Upgraded-Password9!") || passwordOK(st.Password, "old-local-password") {
		t.Fatal("password policy not migrated")
	}
}
func TestReplayRecoveryAndAuthenticatorReplacement(t *testing.T) {
	a := testApp(t)
	cookie, csrf := setup(t, a)
	seed := mustSecret(t, a)
	code := totp(seed, time.Now().Unix()/30)
	if request(t, a, "login", map[string]string{"username": "tester", "password": "Isolated-Example9!password", "code": code}, nil, "").Code != 200 {
		t.Fatal("fresh factor rejected")
	}
	if request(t, a, "login", map[string]string{"username": "tester", "password": "Isolated-Example9!password", "code": code}, nil, "").Code != 401 {
		t.Fatal("factor replay accepted")
	}
	recovery := randomID()
	_ = a.store.update(func(st *State) error {
		st.Recovery = []string{recoveryHash(recovery)}
		st.TOTPLast = time.Now().Unix()/30 - 1
		return nil
	})
	reset := request(t, a, "login", map[string]string{"username": "tester", "password": "Isolated-Example9!password", "code": recovery}, nil, "")
	if reset.Code != 200 {
		t.Fatal("recovery failed")
	}
	if request(t, a, "state", nil, reset.Result().Cookies()[0], "").Code != 403 {
		t.Fatal("recovery code granted direct inbox access")
	}
	if request(t, a, "login", map[string]string{"username": "tester", "password": "Isolated-Example9!password", "code": recovery}, nil, "").Code != 401 {
		t.Fatal("recovery code reused")
	}
	begin := request(t, a, "2fa/begin", map[string]string{"current": "Isolated-Example9!password", "code": code}, cookie, csrf)
	if begin.Code != 200 {
		t.Fatal("step-up enrollment failed")
	}
	var pending struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(begin.Body.Bytes(), &pending)
	next := request(t, a, "2fa/confirm", map[string]string{"code": totp(pending.Secret, time.Now().Unix()/30)}, cookie, csrf)
	if next.Code != 200 {
		t.Fatal("replacement failed")
	}
	if mustSecret(t, a) == seed || len(a.store.snapshot().Recovery) != 10 {
		t.Fatal("old factor retained")
	}
	if request(t, a, "state", nil, cookie, "").Code != 401 {
		t.Fatal("replacement kept old session")
	}
}
func TestStrongPasswordPolicy(t *testing.T) {
	for _, weak := range []string{"short", "longlowercasepassword", "OnlyLettersAnd9", "lowercase-only9!", "UPPERCASE-ONLY9!", "NoDigitsHere!!!"} {
		if strongPassword(weak) {
			t.Fatal("weak password accepted")
		}
	}
	if !strongPassword("Valid-Password9!") {
		t.Fatal("valid password rejected")
	}
}
func TestOutgoingInjectionMIMEAndDeduplication(t *testing.T) {
	a := testApp(t)
	cookie, csrf := setup(t, a)
	_ = a.store.update(func(st *State) error {
		st.Accounts = []Account{{ID: "a", Provider: "qq", Email: "sender@example.org", Authorized: true, Secret: a.store.encrypt("synthetic")}}
		return nil
	})
	old := smtpSubmit
	calls := 0
	smtpSubmit = func(ctx context.Context, acc Account, secret string, o Outgoing) error {
		calls++
		raw, rcpts, e := buildOutgoing(o, acc)
		if e != nil {
			return e
		}
		if len(rcpts) != 3 || strings.Contains(strings.SplitN(string(raw), "\r\n\r\n", 2)[0], "Bcc:") {
			t.Error("BCC privacy or recipients incorrect")
		}
		parsed, e := parseMail(raw)
		if e != nil || !strings.Contains(parsed.Text, "Test body") || len(parsed.Attachments) != 1 {
			t.Error("MIME body or attachment lost")
		}
		return nil
	}
	defer func() { smtpSubmit = old }()
	outgoing := Outgoing{ID: randomID(), AccountID: "a", To: "to@example.org", CC: "cc@example.org", BCC: "hidden@example.org", Subject: "Normal subject", Text: "Test body", Attachments: []SendAttachment{{Name: "file.txt", Data: []byte("hello")}}}
	bad := outgoing
	bad.Subject = "Subject\r\nBcc: attacker@example.org"
	if request(t, a, "send", bad, cookie, csrf).Code != 400 {
		t.Fatal("mail header injection accepted")
	}
	bad = outgoing
	bad.To = "to@example.org\r\nRCPT TO:evil@example.org"
	if request(t, a, "send", bad, cookie, csrf).Code != 400 {
		t.Fatal("recipient injection accepted")
	}
	if request(t, a, "send", outgoing, cookie, csrf).Code != 202 {
		t.Fatal("mail submission failed")
	}
	if request(t, a, "send", outgoing, cookie, csrf).Code != 200 || calls != 1 {
		t.Fatal("duplicate submission")
	}
	if a.store.snapshot().Sent[0].Status != "accepted" {
		t.Fatal("submission not recorded")
	}
}
func TestWebhookTemplateEscapingAndPrivacy(t *testing.T) {
	ch := Channels{WebhookBody: `{"title":"{{title}}","message":"{{text}}","sender":"{{from}}","details":"{{fields}}"}`}
	payload := map[string]any{"event": "mail.received", "subject": "Quote \" and newline\n", "body": "Text \\ ending", "from": "from@example.org"}
	b, typ, e := renderWebhook(ch, payload)
	if e != nil || typ != "application/json" {
		t.Fatal("template failed")
	}
	var decoded map[string]any
	if json.Unmarshal(b, &decoded) != nil || decoded["title"] != payload["subject"] {
		t.Fatal("JSON value escaping failed")
	}
	b, _, e = renderWebhook(ch, map[string]any{"event": "mail.received", "account": "example"})
	if e != nil || strings.Contains(string(b), "from@example.org") || strings.Contains(string(b), "Quote") {
		t.Fatal("notice mode exposed content")
	}
	if _, e = validateHeaders(`{"Authorization":"Bearer a\r\nInjected: b"}`); e == nil {
		t.Fatal("header newline injection accepted")
	}
	if _, e = validateHeaders(`{"Host":"evil.example"}`); e == nil {
		t.Fatal("host override accepted")
	}
}
func TestAllowBlockListsAndChannelScope(t *testing.T) {
	m := Message{ID: "m", AccountID: "a", Sender: "sender@example.org", Subject: "invoice"}
	allow := Rule{ID: "allow", Enabled: true, FilterMode: "allow", SenderList: "@example.org", Mode: "summary", Telegram: true}
	deny := Rule{ID: "deny", Enabled: true, FilterMode: "deny", KeywordList: "invoice", Mode: "notice", Telegram: true}
	if !matches(allow, m) || matches(deny, m) {
		t.Fatal("list matching incorrect")
	}
	deny.AccountID = "other"
	if matches(deny, m) {
		t.Fatal("account scope ignored")
	}
	empty := allow
	empty.SenderList = ""
	if matches(empty, m) {
		t.Fatal("empty allowlist matched")
	}
	deny.AccountID = "a"
	allow.Webhook = true
	st := State{Rules: []Rule{allow, deny}, Messages: []Message{}}
	mergeMessages(&st, Account{ID: "a"}, []Message{m}, true)
	if len(st.Jobs) != 1 || st.Jobs[0].Channel != "webhook" {
		t.Fatal("blocklist did not override allowlist for its channel")
	}
}

func TestBlocklistCancelsQueuedNotifications(t *testing.T) {
	a := testApp(t)
	cookie, csrf := setup(t, a)
	_ = a.store.update(func(st *State) error {
		st.Messages = []Message{{ID: "m", AccountID: "a", Subject: "ads"}}
		st.Jobs = []Job{{ID: "pending", MessageID: "m", Channel: "telegram", Mode: "body"}}
		return nil
	})
	rule := Rule{ID: "block", Name: "block", Enabled: true, FilterMode: "deny", KeywordList: "ads", Telegram: true, Mode: "notice"}
	w := request(t, a, "rules", map[string]any{"rules": []Rule{rule}}, cookie, csrf)
	if w.Code != 200 || !a.store.snapshot().Jobs[0].Canceled {
		t.Fatal("queued notification not canceled")
	}
}

func TestCustomWebhookHeadersArePrivateAndDraftDoesNotSave(t *testing.T) {
	a := testApp(t)
	cookie, csrf := setup(t, a)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "PUT" || r.Header.Get("Authorization") != "Bearer synthetic-private-header" {
			t.Error("custom method/header missing")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["event"] != "mail.test" {
			t.Error("custom JSON body invalid")
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	old := webhookHTTP
	webhookHTTP = server.Client()
	defer func() { webhookHTTP = old }()
	draft := channelDraft{WebhookEnabled: true, WebhookURL: server.URL, WebhookMethod: "PUT", WebhookBodyType: "json", WebhookHeaders: `{"Authorization":"Bearer synthetic-private-header"}`, WebhookBody: `{"event":"{{event}}","text":"{{text}}"}`}
	before := a.store.snapshot().Revision
	if request(t, a, "webhook/test", draft, cookie, csrf).Code != 200 || calls != 1 || a.store.snapshot().Revision != before {
		t.Fatal("draft webhook test changed stored settings")
	}
	if request(t, a, "channels", draft, cookie, csrf).Code != 200 {
		t.Fatal("custom webhook not saved")
	}
	if strings.Contains(request(t, a, "state", nil, cookie, "").Body.String(), "synthetic-private-header") {
		t.Fatal("header secret disclosed")
	}
	plain, e := a.store.decrypt(a.store.snapshot().Channels.WebhookHeaders)
	if e != nil || !strings.Contains(plain, "synthetic-private-header") {
		t.Fatal("encrypted headers not recoverable")
	}
}

func TestDatabaseVersionMigrationAndLiteralSQLText(t *testing.T) {
	dir := t.TempDir()
	s, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	literal := "'; DROP TABLE state; -- <script>not executable</script>"
	_ = s.update(func(st *State) error {
		st.Version = 1
		st.Accounts = []Account{{ID: "a", Name: "example", Secret: s.encrypt("synthetic"), LastUID: 91, UIDValidity: 7, Initialized: true}}
		st.Messages = []Message{{ID: "m", AccountID: "a", Subject: literal}}
		return nil
	})
	s.db.Close()
	migrated, e := openStore(dir)
	if e != nil {
		t.Fatal("legacy migration failed")
	}
	defer migrated.db.Close()
	st := migrated.snapshot()
	if st.Version != 2 || st.Accounts[0].LastUID != 91 || st.Messages[0].Subject != literal {
		t.Fatal("legacy data or literal SQL text altered")
	}
	var count int
	if migrated.db.QueryRow("SELECT COUNT(*) FROM state").Scan(&count) != nil || count != 1 {
		t.Fatal("parameterized persistence was modified by mail text")
	}
}
func TestHTTPProxyTunnelAndEncryptedConfiguration(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "imap.fixture:993" {
			t.Error("wrong proxy destination")
			return
		}
		conn, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		_ = rw.Flush()
		data := make([]byte, 4)
		if _, e = io.ReadFull(rw, data); e == nil {
			_, _ = conn.Write(data)
		}
	}))
	defer proxyServer.Close()
	ctx := context.WithValue(context.Background(), proxyKey{}, proxyServer.URL)
	conn, e := dialProxy(ctx, "imap.fixture:993")
	if e != nil {
		t.Fatal("proxy tunnel failed")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write([]byte("ping"))
	data := make([]byte, 4)
	if _, e = io.ReadFull(conn, data); e != nil || string(data) != "ping" {
		t.Fatal("tunnel data lost")
	}
	a := testApp(t)
	cookie, csrf := setup(t, a)
	raw := strings.Replace(proxyServer.URL, "://", "://synthetic-user:synthetic-pass@", 1)
	w := request(t, a, "account", map[string]any{"provider": "qq", "name": "proxy", "email": "p@example.org", "password": "synthetic", "proxy": raw}, cookie, csrf)
	if w.Code != 200 {
		t.Fatal("proxy configuration rejected")
	}
	saved := a.store.snapshot().Accounts[0]
	plain, e := a.store.decrypt(saved.Proxy)
	if e != nil || plain != raw {
		t.Fatal("proxy credentials not retained")
	}
	if strings.Contains(request(t, a, "state", nil, cookie, "").Body.String(), "synthetic-pass") {
		t.Fatal("proxy credentials exposed")
	}
	if validateProxy("file:///etc/passwd") == nil {
		t.Fatal("proxy scheme unrestricted")
	}
}
