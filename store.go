package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	_ "modernc.org/sqlite"
)

const version = "0.2.2"
const maxMessages = 5000

type Account struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Provider    string `json:"provider"`
	Email       string `json:"email"`
	Enabled     bool   `json:"enabled"`
	Secret      string `json:"secret,omitempty"`
	ClientID    string `json:"clientId"`
	Authorized  bool   `json:"authorized"`
	Cursor      string `json:"cursor,omitempty"`
	UIDValidity uint32 `json:"uidValidity,omitempty"`
	LastUID     uint32 `json:"lastUid,omitempty"`
	Initialized bool   `json:"initialized"`
	LastSync    int64  `json:"lastSync"`
	LastError   string `json:"lastError"`
	Generation  string `json:"generation"`
	Proxy       string `json:"proxy,omitempty"`
}
type Message struct {
	ID          string `json:"id"`
	AccountID   string `json:"accountId"`
	RemoteID    string `json:"remoteId"`
	Subject     string `json:"subject"`
	From        string `json:"from"`
	Sender      string `json:"sender"`
	Date        int64  `json:"date"`
	Read        bool   `json:"read"`
	Starred     bool   `json:"starred"`
	Size        uint32 `json:"size"`
	Attachments bool   `json:"attachments"`
	Preview     string `json:"preview"`
}
type Channels struct {
	TelegramEnabled bool   `json:"telegramEnabled"`
	Token           string `json:"token,omitempty"`
	ChatID          int64  `json:"chatId"`
	BotName         string `json:"botName"`
	WebhookEnabled  bool   `json:"webhookEnabled"`
	WebhookURL      string `json:"webhookUrl"`
	WebhookSecret   string `json:"webhookSecret,omitempty"`
	WebhookHeaders  string `json:"webhookHeaders,omitempty"`
	WebhookBody     string `json:"webhookBody"`
	WebhookMethod   string `json:"webhookMethod"`
	WebhookBodyType string `json:"webhookBodyType"`
}
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	AccountID   string `json:"accountId"`
	Sender      string `json:"sender"`
	Keyword     string `json:"keyword"`
	Mode        string `json:"mode"`
	Telegram    bool   `json:"telegram"`
	Webhook     bool   `json:"webhook"`
	FilterMode  string `json:"filterMode"`
	SenderList  string `json:"senderList"`
	KeywordList string `json:"keywordList"`
}
type Job struct {
	ID        string `json:"id"`
	MessageID string `json:"messageId"`
	RuleID    string `json:"ruleId"`
	Channel   string `json:"channel"`
	Mode      string `json:"mode"`
	Attempts  int    `json:"attempts"`
	Next      int64  `json:"next"`
	Done      bool   `json:"done"`
	Canceled  bool   `json:"canceled,omitempty"`
	Error     string `json:"error"`
}
type Event struct {
	Time int64  `json:"time"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}
type State struct {
	Version        int          `json:"version"`
	Revision       int64        `json:"revision"`
	Username       string       `json:"username"`
	Password       string       `json:"password"`
	PasswordPolicy int          `json:"passwordPolicy"`
	AuthEpoch      string       `json:"authEpoch"`
	TOTPSecret     string       `json:"totpSecret,omitempty"`
	TOTPLast       int64        `json:"totpLast"`
	Recovery       []string     `json:"recovery,omitempty"`
	Sent           []SendRecord `json:"sent,omitempty"`
	Accounts       []Account    `json:"accounts"`
	Messages       []Message    `json:"messages"`
	Channels       Channels     `json:"channels"`
	Rules          []Rule       `json:"rules"`
	Jobs           []Job        `json:"jobs"`
	Events         []Event      `json:"events"`
}
type Store struct {
	mu    sync.Mutex
	db    *sql.DB
	key   []byte
	state State
}

func randomID() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic("system random unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func seal(key, plain []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return g.Seal(nonce, nonce, plain, []byte("mail-harbor.v1")), nil
}
func unseal(key, data []byte) ([]byte, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	if len(data) < g.NonceSize() {
		return nil, errors.New("invalid encrypted data")
	}
	return g.Open(nil, data[:g.NonceSize()], data[g.NonceSize():], []byte("mail-harbor.v1"))
}
func (s *Store) encrypt(text string) string {
	if text == "" {
		return ""
	}
	b, e := seal(s.key, []byte(text))
	if e != nil {
		panic("credential encryption failed")
	}
	return base64.RawStdEncoding.EncodeToString(b)
}
func (s *Store) decrypt(text string) (string, error) {
	if text == "" {
		return "", nil
	}
	b, e := base64.RawStdEncoding.DecodeString(text)
	if e != nil {
		return "", e
	}
	b, e = unseal(s.key, b)
	return string(b), e
}
func passwordHash(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	out := pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
	return base64.RawStdEncoding.EncodeToString(append(salt, out...))
}
func passwordOK(hash, password string) bool {
	b, e := base64.RawStdEncoding.DecodeString(hash)
	if e != nil || len(b) != 48 {
		return false
	}
	out := pbkdf2.Key([]byte(password), b[:16], 600000, 32, sha256.New)
	return subtle.ConstantTimeCompare(out, b[16:]) == 1
}
func openStore(dir string) (*Store, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, storageError("create data directory", e)
	}
	// Existing bind mounts keep their host/NAS modes. Writable directories need
	// not be owned by this process, and chmod may be unsupported by their ACLs.
	key, e := loadMasterKey(dir)
	if e != nil {
		return nil, e
	}
	dbPath := filepath.Join(dir, "mail-harbor.db")
	if e = regularDataPath(dbPath); e != nil {
		return nil, e
	}
	file, e := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, storageError("open database for writing", e)
	}
	if e = file.Close(); e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", dbPath)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	opened := false
	defer func() {
		if !opened {
			db.Close()
		}
	}()
	if _, e = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL)`); e != nil {
		return nil, e
	}
	s := &Store{db: db, key: key, state: State{Version: 2, Accounts: []Account{}, Messages: []Message{}, Rules: []Rule{}, Jobs: []Job{}, Events: []Event{}}}
	var b []byte
	e = db.QueryRow("SELECT payload FROM state WHERE id=1").Scan(&b)
	if e == sql.ErrNoRows {
		e = s.persist(s.state)
	} else if e == nil {
		e = json.Unmarshal(b, &s.state)
	}
	if e != nil {
		return nil, e
	}
	if s.state.Version != 1 && s.state.Version != 2 {
		return nil, errors.New("unsupported database version")
	}
	for _, a := range s.state.Accounts {
		if _, e = s.decrypt(a.Secret); e != nil {
			return nil, errors.New("account credentials cannot be decrypted; master.key does not match database")
		}
		if _, e = s.decrypt(a.Proxy); e != nil {
			return nil, errors.New("proxy credentials cannot be decrypted; master.key does not match database")
		}
	}
	for _, encrypted := range []string{s.state.TOTPSecret, s.state.Channels.Token, s.state.Channels.WebhookSecret, s.state.Channels.WebhookHeaders} {
		if _, e = s.decrypt(encrypted); e != nil {
			return nil, errors.New("security/notification settings cannot be decrypted; master.key does not match database; retain the original files and restore the matching complete backup")
		}
	}
	if s.state.Version == 1 {
		s.state.Version = 2
		if e = s.persist(s.state); e != nil {
			return nil, e
		}
	}
	opened = true
	return s, nil
}
func cloneState(st State) State {
	b, _ := json.Marshal(st)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}
func (s *Store) snapshot() State { s.mu.Lock(); defer s.mu.Unlock(); return cloneState(s.state) }
func (s *Store) authState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	return State{Username: st.Username, Password: st.Password, PasswordPolicy: st.PasswordPolicy, AuthEpoch: st.AuthEpoch, TOTPSecret: st.TOTPSecret, TOTPLast: st.TOTPLast, Recovery: append([]string{}, st.Recovery...)}
}
func (s *Store) persist(st State) error {
	b, e := json.Marshal(st)
	if e != nil {
		return e
	}
	_, e = s.db.Exec("INSERT INTO state(id,payload) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", b)
	return e
}
func (s *Store) update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if e := fn(&next); e != nil {
		return e
	}
	next.Revision++
	if len(next.Events) > 150 {
		next.Events = next.Events[len(next.Events)-150:]
	}
	if len(next.Messages) > maxMessages {
		next.Messages = next.Messages[len(next.Messages)-maxMessages:]
	}
	if len(next.Jobs) > 10000 {
		kept := []Job{}
		for _, j := range next.Jobs {
			if !j.Done {
				kept = append(kept, j)
			}
		}
		if len(kept) > 10000 {
			return errors.New("notification queue full")
		}
		next.Jobs = kept
	}
	if e := s.persist(next); e != nil {
		return e
	}
	s.state = next
	return nil
}
func event(st *State, kind, text string) {
	st.Events = append(st.Events, Event{time.Now().Unix(), kind, text})
}
func findAccount(st State, id string) (Account, bool) {
	for _, a := range st.Accounts {
		if a.ID == id {
			return a, true
		}
	}
	return Account{}, false
}
func findMessage(st State, id string) (Message, bool) {
	for _, m := range st.Messages {
		if m.ID == id {
			return m, true
		}
	}
	return Message{}, false
}
