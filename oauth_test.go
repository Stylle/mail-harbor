package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func mockJSON(data string) *http.Response {
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(data)), Header: make(http.Header)}
}
func TestMicrosoftDeviceAuthorizationAndRotation(t *testing.T) {
	app := testApp(t)
	cookie, csrf := setup(t, app)
	id := "11111111-1111-1111-1111-111111111111"
	w := request(t, app, "account", map[string]any{"name": "outlook", "provider": "outlook", "email": "test@outlook.com", "enabled": true, "clientId": id}, cookie, csrf)
	if w.Code != 200 {
		t.Fatal("cannot save account")
	}
	acc := app.store.snapshot().Accounts[0]
	old := externalHTTP
	externalHTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/devicecode"):
			return mockJSON(`{"device_code":"synthetic-device","user_code":"EXAMPLE","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`), nil
		case strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "grant_type=refresh_token") {
				return mockJSON(`{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}`), nil
			}
			return mockJSON(`{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":3600}`), nil
		case r.URL.Host == "graph.microsoft.com" && r.URL.Path == "/v1.0/me":
			return mockJSON(`{"mail":"test@outlook.com","userPrincipalName":"test@outlook.com"}`), nil
		}
		t.Error("unexpected OAuth network request")
		return mockJSON(`{}`), nil
	})}
	defer func() { externalHTTP = old }()
	start := request(t, app, "outlook/start", map[string]string{"id": acc.ID}, cookie, csrf)
	if start.Code != 200 {
		t.Fatal("device start failed")
	}
	var grant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(start.Body.Bytes(), &grant)
	app.mu.Lock()
	g := app.grants[grant.ID]
	g.Next = 0
	app.grants[grant.ID] = g
	app.mu.Unlock()
	poll := request(t, app, "outlook/poll", map[string]string{"id": grant.ID}, cookie, csrf)
	if poll.Code != 200 {
		t.Fatal("device poll failed")
	}
	acc = app.store.snapshot().Accounts[0]
	if !acc.Authorized {
		t.Fatal("account not authorized")
	}
	secret, e := app.store.decrypt(acc.Secret)
	if e != nil || !strings.Contains(secret, "synthetic-refresh") {
		t.Fatal("refresh token not encrypted and retained")
	}
	if strings.Contains(request(t, app, "state", nil, cookie, "").Body.String(), "synthetic-refresh") {
		t.Fatal("OAuth token leaked")
	}
	tok := msTokens{Refresh: "expired-refresh", Until: time.Now().Unix() - 1}
	data, _ := json.Marshal(tok)
	renewed, e := refreshMS(context.Background(), acc, string(data))
	if e != nil || renewed.Refresh != "rotated-refresh" || renewed.Until <= time.Now().Unix() {
		t.Fatal("refresh rotation failed", e)
	}
}
func TestGraphDeltaPaginationAndReadOnlyDetail(t *testing.T) {
	old := externalHTTP
	calls := 0
	externalHTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Error("invalid read-only request")
		}
		switch {
		case strings.Contains(r.URL.Path, "/messages/delta"):
			if r.URL.Query().Get("page") == "2" {
				return mockJSON(`{"value":[{"id":"second","subject":"Second","receivedDateTime":"2026-11-16T08:00:00Z","from":{"emailAddress":{"name":"Sender","address":"s@example.org"}}}],"@odata.deltaLink":"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?token=next"}`), nil
			}
			if r.URL.Query().Get("token") == "next" {
				return mockJSON(`{"value":[],"@odata.deltaLink":"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?token=next"}`), nil
			}
			return mockJSON(`{"value":[{"id":"first","subject":"First","receivedDateTime":"2026-11-15T08:00:00Z"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?page=2"}`), nil
		case strings.HasSuffix(r.URL.Path, "/attachments"):
			return mockJSON(`{"value":[{"@odata.type":"#microsoft.graph.fileAttachment","name":"sample.txt","size":5,"contentBytes":"aGVsbG8="}]}`), nil
		default:
			return mockJSON(`{"body":{"contentType":"text","content":"Example body"}}`), nil
		}
	})}
	defer func() { externalHTTP = old }()
	acc := Account{ID: "a", Provider: "outlook"}
	msgs, next, e := graphHeaders(context.Background(), acc, "synthetic")
	if e != nil || len(msgs) != 2 || !next.Initialized || !strings.Contains(next.Cursor, "token=next") {
		t.Fatal("delta pagination failed", e)
	}
	none, _, e := graphHeaders(context.Background(), next, "synthetic")
	if e != nil || len(none) != 0 {
		t.Fatal("delta checkpoint ignored", e)
	}
	msgs[0].Attachments = true
	body, e := graphDetail(context.Background(), "synthetic", msgs[0])
	if e != nil || body.Text != "Example body" || len(body.Attachments) != 1 || string(body.files[0]) != "hello" {
		t.Fatal("graph detail or attachments failed", e)
	}
	if calls != 5 {
		t.Fatal("unexpected network count")
	}
}
