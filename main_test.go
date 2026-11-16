package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/emersion/go-imap/backend/memory"
	"github.com/emersion/go-imap/server"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	s, e := openStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.db.Close() })
	return &App{store: s, engine: newEngine(s), sessions: map[string]session{}, grants: map[string]deviceGrant{}, limits: map[string]loginLimit{}}
}
func request(t *testing.T, a *App, path string, data any, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if data == nil {
		r = httptest.NewRequest("GET", "http://local.test/api/"+path, nil)
	} else {
		b, _ := json.Marshal(data)
		r = httptest.NewRequest("POST", "http://local.test/api/"+path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func setup(t *testing.T, a *App) (*http.Cookie, string) {
	t.Helper()
	w := request(t, a, "setup", map[string]string{"username": "tester", "password": "isolated-example-password"}, nil, "")
	if w.Code != 200 {
		t.Fatal("setup failed", w.Code)
	}
	var v struct {
		CSRF string `json:"csrf"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return w.Result().Cookies()[0], v.CSRF
}

func TestAuthenticationAndSecretRedaction(t *testing.T) {
	a := testApp(t)
	cookie, csrf := setup(t, a)
	if request(t, a, "state", nil, nil, "").Code != 401 {
		t.Fatal("private state exposed")
	}
	if request(t, a, "account", map[string]any{}, cookie, "").Code != 403 {
		t.Fatal("CSRF missing was accepted")
	}
	r := httptest.NewRequest("POST", "http://local.test/api/logout", strings.NewReader("{}"))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("X-CSRF-Token", csrf)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("cross-origin accepted")
	}
	draft := map[string]any{"name": "test", "provider": "qq", "email": "test@example.com", "enabled": false, "password": "synthetic-credential"}
	w = request(t, a, "account", draft, cookie, csrf)
	if w.Code != 200 {
		t.Fatal("account save failed", w.Code)
	}
	st := a.store.snapshot()
	if strings.Contains(st.Accounts[0].Secret, "synthetic-credential") {
		t.Fatal("plaintext credential persisted")
	}
	got, e := a.store.decrypt(st.Accounts[0].Secret)
	if e != nil || got != "synthetic-credential" {
		t.Fatal("cannot decrypt own credentials")
	}
	public := request(t, a, "state", nil, cookie, "").Body.String()
	if strings.Contains(public, "synthetic-credential") || strings.Contains(public, st.Password) || strings.Contains(public, st.Accounts[0].Secret) {
		t.Fatal("secret leaked")
	}
	w = request(t, a, "security", map[string]string{"current": "isolated-example-password", "username": "changed", "password": "replacement-test-password"}, cookie, csrf)
	if w.Code != 200 {
		t.Fatal("password change failed")
	}
	if request(t, a, "state", nil, cookie, "").Code != 401 {
		t.Fatal("old session survived")
	}
	if request(t, a, "login", map[string]string{"username": "tester", "password": "isolated-example-password"}, nil, "").Code != 401 {
		t.Fatal("old login survived")
	}
	if request(t, a, "login", map[string]string{"username": "changed", "password": "replacement-test-password"}, nil, "").Code != 200 {
		t.Fatal("new login rejected")
	}
}
func TestStorePersistenceAndKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	s, e := openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	e = s.update(func(st *State) error {
		st.Accounts = append(st.Accounts, Account{ID: "a", Secret: s.encrypt("synthetic")})
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	s.db.Close()
	s, e = openStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(s.snapshot().Accounts) != 1 {
		t.Fatal("lost state on restart")
	}
	s.db.Close()
	_ = os.WriteFile(filepath.Join(dir, "master.key"), bytes.Repeat([]byte{2}, 32), 0600)
	if _, e = openStore(dir); e == nil {
		t.Fatal("mismatched key silently accepted")
	}
}
func TestBackupAcrossMasterKeysAndAtomicRestore(t *testing.T) {
	source := testApp(t)
	cookie, csrf := setup(t, source)
	_ = source.store.update(func(st *State) error {
		st.Accounts = []Account{{ID: "a", Name: "example", Provider: "qq", Email: "a@example.com", Secret: source.store.encrypt("synthetic-app-password"), Generation: "old", LastUID: 90, UIDValidity: 7, Initialized: true}}
		st.Channels.Token = source.store.encrypt("synthetic-bot-secret")
		st.Messages = []Message{{ID: "m", AccountID: "a", RemoteID: "90", Subject: "private subject", Starred: true}}
		return nil
	})
	backup := request(t, source, "backup", map[string]string{"password": "portable-backup-password"}, cookie, csrf)
	if backup.Code != 200 {
		t.Fatal("backup failed")
	}
	if bytes.Contains(backup.Body.Bytes(), []byte("private subject")) || bytes.Contains(backup.Body.Bytes(), []byte("synthetic-app-password")) {
		t.Fatal("backup not encrypted")
	}
	target := testApp(t)
	tc, ts := setup(t, target)
	before := target.store.snapshot()
	data := base64.StdEncoding.EncodeToString(backup.Body.Bytes())
	bad := request(t, target, "restore", map[string]string{"password": "incorrect-password", "data": data}, tc, ts)
	if bad.Code != 400 || target.store.snapshot().Revision != before.Revision {
		t.Fatal("bad restore modified state")
	}
	good := request(t, target, "restore", map[string]string{"password": "portable-backup-password", "data": data}, tc, ts)
	if good.Code != 200 {
		t.Fatal("restore failed", good.Code)
	}
	restored := target.store.snapshot()
	plain, e := target.store.decrypt(restored.Accounts[0].Secret)
	if e != nil || plain != "synthetic-app-password" {
		t.Fatal("cross-machine secret not portable")
	}
	if restored.Accounts[0].LastUID != 90 || !restored.Messages[0].Starred {
		t.Fatal("checkpoint or preference lost")
	}
	if request(t, target, "state", nil, tc, "").Code != 401 {
		t.Fatal("restore did not revoke sessions")
	}
}
func TestHistoryBaselineDedupeAndLocalFlags(t *testing.T) {
	st := State{Messages: []Message{}, Rules: []Rule{{ID: "r", Enabled: true, Mode: "notice", Telegram: true, Webhook: true}}}
	acc := Account{ID: "a"}
	m := Message{ID: "m1", AccountID: "a", Subject: "Example", Date: 1}
	mergeMessages(&st, acc, []Message{m}, false)
	if len(st.Jobs) != 0 {
		t.Fatal("history notified")
	}
	m2 := m
	m2.ID = "m2"
	m2.Date = 2
	mergeMessages(&st, acc, []Message{m2}, true)
	if len(st.Jobs) != 2 {
		t.Fatal("channels not queued")
	}
	st.Messages[1].Starred = true
	st.Messages[1].Read = true
	mergeMessages(&st, acc, []Message{m2}, true)
	if len(st.Jobs) != 2 || !st.Messages[1].Starred || !st.Messages[1].Read {
		t.Fatal("duplicate push or flags overwritten")
	}
	if matches(Rule{Enabled: true, Keyword: "invoice"}, m) {
		t.Fatal("filter ignored")
	}
}
func TestMIMEHTMLAndAttachments(t *testing.T) {
	raw := "From: sender@example.org\r\nSubject: =?UTF-8?B?5rWL6K+V?=\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=test\r\n\r\n--test\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <b>reader</b></p><script>danger()</script><img src=\"https://tracking.example/pixel\">\r\n--test\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=test.txt\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--test--\r\n"
	parsed, e := parseMail([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(parsed.Text, "Hello reader") || strings.Contains(parsed.Text, "danger") || strings.Contains(parsed.Text, "tracking.example") {
		t.Fatal("HTML content not reduced to safe text")
	}
	if len(parsed.Attachments) != 1 || string(parsed.files[parsed.Attachments[0].Index]) != "hello" {
		t.Fatal("attachment lost")
	}
}
func TestWebhookSigningAndRetryQueue(t *testing.T) {
	a := testApp(t)
	secret := "synthetic-webhook-key"
	calls := 0
	failFirst := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		stamp := r.Header.Get("X-Mail-Harbor-Timestamp")
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(stamp + "."))
		mac.Write(body)
		if r.Header.Get("X-Mail-Harbor-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Error("signature mismatch")
		}
		if r.Header.Get("Idempotency-Key") == "" {
			t.Error("no delivery identity")
		}
		if bytes.Contains(body, []byte("hidden subject")) {
			t.Error("notice mode leaked subject")
		}
		if failFirst {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer server.Close()
	old := webhookHTTP
	webhookHTTP = server.Client()
	defer func() { webhookHTTP = old }()
	_ = a.store.update(func(st *State) error {
		st.Channels = Channels{WebhookEnabled: true, WebhookURL: server.URL, WebhookSecret: a.store.encrypt(secret)}
		st.Accounts = []Account{{ID: "a", Name: "example"}}
		st.Messages = []Message{{ID: "m", AccountID: "a", Subject: "hidden subject"}}
		st.Jobs = []Job{{ID: "j", MessageID: "m", Channel: "webhook", Mode: "notice"}}
		return nil
	})
	a.engine.deliver(context.Background())
	job := a.store.snapshot().Jobs[0]
	if job.Done || job.Attempts != 1 || job.Next <= time.Now().Unix() {
		t.Fatal("retry state not persisted")
	}
	a.engine.deliver(context.Background())
	if calls != 1 {
		t.Fatal("backoff ignored")
	}
	_ = a.store.update(func(st *State) error { st.Jobs[0].Next = 0; return nil })
	failFirst = false
	a.engine.deliver(context.Background())
	a.engine.deliver(context.Background())
	if calls != 2 || !a.store.snapshot().Jobs[0].Done {
		t.Fatal("delivery repeated after success")
	}
}
func TestGraphRejectsForeignCursor(t *testing.T) {
	var out any
	for _, endpoint := range []string{"http://graph.microsoft.com/v1.0/me/messages", "https://evil.example/v1.0/me/messages", "https://graph.microsoft.com/v1.0/users/other/messages"} {
		if graphGet(context.Background(), "synthetic", endpoint, &out) == nil {
			t.Fatal("unsafe cursor accepted")
		}
	}
}
func TestIMAPBaselineIncrementalAndPeek(t *testing.T) {
	be := memory.New()
	user, e := be.Login(nil, "username", "password")
	if e != nil {
		t.Fatal(e)
	}
	mb, e := user.GetMailbox("INBOX")
	if e != nil {
		t.Fatal(e)
	}
	box := mb.(*memory.Mailbox)
	box.Messages[0].Flags = []string{}
	srv := server.New(be)
	srv.AllowInsecureAuth = true
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go srv.Serve(ln)
	defer srv.Close()
	old := imapDial
	imapDial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", ln.Addr().String())
	}
	defer func() { imapDial = old }()
	acc := Account{ID: "a", Provider: "qq", Email: "username"}
	headers, next, e := imapHeaders(context.Background(), acc, "password")
	if e != nil || len(headers) != 1 || !next.Initialized || next.LastUID != 6 {
		t.Fatal("baseline failed", e)
	}
	detail, e := imapDetail(context.Background(), next, "password", headers[0])
	if e != nil || !strings.Contains(detail.Text, "Hi there") {
		t.Fatal("body retrieval failed", e)
	}
	if len(box.Messages[0].Flags) != 0 {
		t.Fatal("reading marked upstream mail seen")
	}
	raw := "From: next@example.com\r\nSubject: Next message\r\nContent-Type: text/plain\r\n\r\nNext body"
	if e = box.CreateMessage(nil, time.Now(), strings.NewReader(raw)); e != nil {
		t.Fatal(e)
	}
	fresh, last, e := imapHeaders(context.Background(), next, "password")
	if e != nil || len(fresh) != 1 || fresh[0].Subject != "Next message" || last.LastUID <= next.LastUID {
		t.Fatal("incremental fetch failed", e)
	}
	none, _, e := imapHeaders(context.Background(), last, "password")
	if e != nil || len(none) != 0 {
		t.Fatal("old UIDs re-fetched", e)
	}
	stale := last
	stale.UIDValidity = 999
	reset, reindexed, e := imapHeaders(context.Background(), stale, "password")
	if e != nil || len(reset) != 2 || reindexed.UIDValidity == 999 {
		t.Fatal("UIDVALIDITY change not recovered", e)
	}
}
