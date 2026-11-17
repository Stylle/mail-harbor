package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultWebhookHasFormattedTitleAndCompleteContent(t *testing.T) {
	body := strings.Repeat("完整正文\n", 4000) + "last line: \"quoted\" & <text>"
	m := Message{Subject: "本期账单", Sender: "sender@example.org", Date: 1794825600}
	payload := notificationPayload("工作邮箱", m, Job{ID: "synthetic", Mode: "body"}, body)
	b, kind, e := renderWebhook(Channels{}, payload)
	if e != nil || kind != "application/json" {
		t.Fatal("default format failed")
	}
	var out map[string]string
	if e = json.Unmarshal(b, &out); e != nil || len(out) != 2 || out["title"] != m.Subject {
		t.Fatal("default JSON shape is not title/content")
	}
	for _, part := range []string{"发件人：sender@example.org", "接收邮箱：工作邮箱", "收信时间：", "\n\n" + body} {
		if !strings.Contains(out["content"], part) {
			t.Fatal("formatted content lost metadata or complete body")
		}
	}
	if !strings.HasSuffix(out["content"], body) {
		t.Fatal("long body was truncated or rewritten")
	}
}

func TestDefaultWebhookRespectsNoticePrivacyAndCustomTemplates(t *testing.T) {
	m := Message{Subject: "private subject", Sender: "private-sender@example.org", Date: 1794825600}
	payload := notificationPayload("账号别名", m, Job{Mode: "notice"}, "private body")
	for _, ch := range []Channels{{}, {WebhookBodyType: "text"}, {WebhookBody: `{"raw":"{{fields}}","content":"{{content}}"}`}} {
		b, _, e := renderWebhook(ch, payload)
		if e != nil {
			t.Fatal(e)
		}
		for _, blocked := range []string{m.Subject, m.Sender, "private body"} {
			if strings.Contains(string(b), blocked) {
				t.Fatal("notice mode leaked mail details")
			}
		}
		if !strings.Contains(string(b), "账号别名") {
			t.Fatal("receiving account display name lost")
		}
	}
	custom := Channels{WebhookBody: `{"message":"{{text}}","name":"{{account}}"}`}
	b, _, e := renderWebhook(custom, notificationPayload("收件别名", m, Job{Mode: "body"}, "original body"))
	if e != nil {
		t.Fatal(e)
	}
	var out map[string]string
	if json.Unmarshal(b, &out) != nil || out["message"] != "original body" || out["name"] != "收件别名" {
		t.Fatal("existing custom format changed")
	}
}
