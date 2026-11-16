package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	qrcode "github.com/skip2/go-qrcode"
)

const passwordRequirement = "密码至少12个字符，必须包含大写字母、小写字母、数字和符号"

func strongPassword(p string) bool {
	if utf8.RuneCountInString(p) < 12 || len(p) > 256 {
		return false
	}
	var upper, lower, digit, symbol bool
	for _, r := range p {
		upper = upper || unicode.IsUpper(r)
		lower = lower || unicode.IsLower(r)
		digit = digit || unicode.IsDigit(r)
		symbol = symbol || unicode.IsPunct(r) || unicode.IsSymbol(r)
	}
	return upper && lower && digit && symbol
}
func totp(secret string, step int64) string {
	key, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1000000)
}
func verifyTOTP(secret, code string, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	step := time.Now().Unix() / 30
	for _, s := range []int64{step, step - 1, step + 1} {
		if s > last && subtle.ConstantTimeCompare([]byte(totp(secret, s)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}
func recoveryHash(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))))
	return hex.EncodeToString(sum[:])
}

type enrollment struct {
	Secret, Epoch, Password string
	Until                   int64
	Attempts                int
}

func (a *App) issueSession(w http.ResponseWriter, r *http.Request, full bool, recovery bool, expected State) {
	st := a.store.authState()
	token := randomID()
	duration := int64(7 * 86400)
	if !full {
		duration = 600
	}
	s := session{CSRF: randomID(), Until: time.Now().Unix() + duration, Full: full, ReEnroll: recovery, Epoch: st.AuthEpoch}
	a.mu.Lock()
	current := a.store.authState()
	if current.Password != expected.Password || current.AuthEpoch != expected.AuthEpoch {
		a.mu.Unlock()
		fail(w, 401, "管理账户已改变，请重新登录")
		return
	}
	for key, old := range a.sessions {
		if old.Until < time.Now().Unix() {
			delete(a.sessions, key)
		}
	}
	if len(a.sessions) >= 100 {
		a.sessions = map[string]session{}
	}
	a.sessions[sessionKey(token)] = s
	a.mu.Unlock()
	secure := r.TLS != nil || (r.Header.Get("X-Forwarded-Proto") == "https" && trustProxy())
	http.SetCookie(w, &http.Cookie{Name: "mail_harbor", Value: token, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(duration)})
	jsonOut(w, 200, map[string]any{"configured": true, "authenticated": full, "needsTwoFactorSetup": !full, "needsPasswordChange": st.PasswordPolicy < 1, "twoFactorRequired": st.TOTPSecret != "", "csrf": s.CSRF, "username": st.Username})
}
func (a *App) consumeSecondFactor(st State, code string, allowRecovery bool) (bool, bool) {
	secret, e := a.store.decrypt(st.TOTPSecret)
	if e != nil {
		return false, false
	}
	step, valid := verifyTOTP(secret, strings.TrimSpace(code), st.TOTPLast)
	isRecovery := false
	index := -1
	if !valid && allowRecovery && len(code) > 10 {
		hash := recoveryHash(code)
		for i, v := range st.Recovery {
			if subtle.ConstantTimeCompare([]byte(v), []byte(hash)) == 1 {
				index = i
				valid = true
				isRecovery = true
				break
			}
		}
	}
	if !valid {
		return false, false
	}
	e = a.store.update(func(next *State) error {
		if next.Password != st.Password || next.TOTPSecret != st.TOTPSecret || next.AuthEpoch != st.AuthEpoch {
			return fmt.Errorf("account changed")
		}
		if isRecovery {
			if index >= len(next.Recovery) || next.Recovery[index] != st.Recovery[index] {
				return fmt.Errorf("recovery used")
			}
			next.Recovery = append(next.Recovery[:index], next.Recovery[index+1:]...)
		} else {
			if step <= next.TOTPLast {
				return fmt.Errorf("code used")
			}
			next.TOTPLast = step
		}
		return nil
	})
	return e == nil, isRecovery
}
func (a *App) beginEnrollment(w http.ResponseWriter, r *http.Request, key string, s session) {
	var v struct {
		Current string `json:"current"`
		Code    string `json:"code"`
	}
	if !decode(w, r, &v) {
		return
	}
	st := a.store.authState()
	if s.Full {
		if !passwordOK(st.Password, v.Current) {
			fail(w, 400, "当前密码不正确")
			return
		}
		if ok, _ := a.consumeSecondFactor(st, v.Code, false); !ok {
			fail(w, 400, "验证码不正确或已使用，请等待下一组验证码")
			return
		}
	}
	seed := make([]byte, 20)
	if _, e := rand.Read(seed); e != nil {
		fail(w, 500, "验证器初始化失败")
		return
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	uri := "otpauth://totp/" + url.PathEscape("Mail Harbor:"+st.Username) + "?" + url.Values{"secret": {secret}, "issuer": {"Mail Harbor"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()
	png, e := qrcode.Encode(uri, qrcode.Medium, 240)
	if e != nil {
		fail(w, 500, "验证器初始化失败")
		return
	}
	a.mu.Lock()
	if a.enrollments == nil {
		a.enrollments = map[string]enrollment{}
	}
	for k, v := range a.enrollments {
		if v.Until < time.Now().Unix() {
			delete(a.enrollments, k)
		}
	}
	a.enrollments[key] = enrollment{Secret: secret, Epoch: st.AuthEpoch, Password: st.Password, Until: time.Now().Unix() + 600}
	a.mu.Unlock()
	jsonOut(w, 200, map[string]any{"secret": secret, "qr": png, "expires": 600, "needsPasswordChange": st.PasswordPolicy < 1})
}
func (a *App) confirmEnrollment(w http.ResponseWriter, r *http.Request, key string) {
	var v struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if !decode(w, r, &v) {
		return
	}
	a.mu.Lock()
	pending, ok := a.enrollments[key]
	if ok {
		pending.Attempts++
		a.enrollments[key] = pending
	}
	a.mu.Unlock()
	if !ok || pending.Until < time.Now().Unix() || pending.Attempts > 10 {
		fail(w, 400, "验证器绑定已过期，请重新开始")
		return
	}
	step, valid := verifyTOTP(pending.Secret, v.Code, 0)
	if !valid {
		fail(w, 400, "验证码不正确，请检查验证器时间")
		return
	}
	st := a.store.authState()
	if (st.PasswordPolicy < 1 || v.Password != "") && !strongPassword(v.Password) {
		fail(w, 400, passwordRequirement)
		return
	}
	hash := st.Password
	if v.Password != "" {
		hash = passwordHash(v.Password)
	}
	codes := []string{}
	hashes := []string{}
	for i := 0; i < 10; i++ {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		code := strings.ToUpper(hex.EncodeToString(b))
		code = code[:8] + "-" + code[8:16] + "-" + code[16:]
		codes = append(codes, code)
		hashes = append(hashes, recoveryHash(code))
	}
	err := a.store.update(func(next *State) error {
		if next.AuthEpoch != pending.Epoch || next.Password != pending.Password {
			return fmt.Errorf("account changed")
		}
		next.Password = hash
		next.PasswordPolicy = 1
		next.TOTPSecret = a.store.encrypt(pending.Secret)
		next.TOTPLast = step
		next.Recovery = hashes
		next.AuthEpoch = randomID()
		event(next, "security", "双重验证已启用，旧登录与旧验证器已失效")
		return nil
	})
	if err != nil {
		fail(w, 409, "账户已改变，请重新登录")
		return
	}
	a.clearSessions()
	// Do not expose recovery codes through the generic session endpoint.
	st = a.store.authState()
	token := randomID()
	s := session{CSRF: randomID(), Until: time.Now().Unix() + 7*86400, Full: true, Epoch: st.AuthEpoch}
	a.mu.Lock()
	a.sessions[sessionKey(token)] = s
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "mail_harbor", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || (trustProxy() && r.Header.Get("X-Forwarded-Proto") == "https"), MaxAge: 7 * 86400})
	jsonOut(w, 200, map[string]any{"csrf": s.CSRF, "username": st.Username, "authenticated": true, "needsTwoFactorSetup": false, "needsPasswordChange": false, "twoFactorRequired": true, "recoveryCodes": codes})
}
