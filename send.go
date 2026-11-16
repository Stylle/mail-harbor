package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	stdmail "net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/emersion/go-message/mail"
)

type SendAttachment struct {
	Name        string `json:"name"`
	ContentType string `json:"contentType"`
	Data        []byte `json:"data"`
}
type Outgoing struct {
	ID          string           `json:"id"`
	AccountID   string           `json:"accountId"`
	To          string           `json:"to"`
	CC          string           `json:"cc"`
	BCC         string           `json:"bcc"`
	Subject     string           `json:"subject"`
	Text        string           `json:"text"`
	Attachments []SendAttachment `json:"attachments"`
}
type SendRecord struct {
	ID        string `json:"id"`
	AccountID string `json:"accountId"`
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Time      int64  `json:"time"`
	Status    string `json:"status"`
}

var smtpHosts = map[string]string{"qq": "smtp.qq.com:465", "163": "smtp.163.com:465", "gmail": "smtp.gmail.com:465"}

func recipients(raw string) ([]*stdmail.Address, error) {
	if raw == "" {
		return nil, nil
	}
	if strings.ContainsAny(raw, "\r\n") || len(raw) > 8000 {
		return nil, errors.New("收件地址无效")
	}
	list, e := stdmail.ParseAddressList(strings.ReplaceAll(raw, ";", ","))
	if e != nil {
		return nil, errors.New("请填写有效的收件邮箱地址")
	}
	return list, nil
}
func validateOutgoing(o Outgoing) ([]*stdmail.Address, []*stdmail.Address, []*stdmail.Address, error) {
	to, e := recipients(o.To)
	if e != nil {
		return nil, nil, nil, e
	}
	cc, e := recipients(o.CC)
	if e != nil {
		return nil, nil, nil, e
	}
	bcc, e := recipients(o.BCC)
	if e != nil {
		return nil, nil, nil, e
	}
	if len(to) == 0 || len(to)+len(cc)+len(bcc) > 50 || len(o.ID) < 16 || len(o.ID) > 100 || strings.ContainsAny(o.Subject, "\r\n") || len(o.Subject) > 1000 || len(o.Text) > 1<<20 || len(o.Attachments) > 10 {
		return nil, nil, nil, errors.New("请检查收件人、主题和正文；最多50个收件人、10个附件")
	}
	total := 0
	for _, att := range o.Attachments {
		total += len(att.Data)
		if att.Name == "" || len(att.Name) > 255 || strings.ContainsAny(att.Name, "\r\n\x00") {
			return nil, nil, nil, errors.New("附件名称无效")
		}
	}
	if total > 8<<20 {
		return nil, nil, nil, errors.New("附件合计不能超过8MB")
	}
	return to, cc, bcc, nil
}
func buildOutgoing(o Outgoing, acc Account) ([]byte, []string, error) {
	to, cc, bcc, e := validateOutgoing(o)
	if e != nil {
		return nil, nil, e
	}
	from, e := stdmail.ParseAddress(acc.Email)
	if e != nil {
		return nil, nil, e
	}
	var h mail.Header
	h.SetAddressList("From", []*stdmail.Address{from})
	h.SetAddressList("To", to)
	if len(cc) > 0 {
		h.SetAddressList("Cc", cc)
	}
	h.SetSubject(o.Subject)
	h.SetDate(time.Now())
	_ = h.GenerateMessageIDWithHostname("mail-harbor.local")
	var b bytes.Buffer
	w, e := mail.CreateWriter(&b, h)
	if e != nil {
		return nil, nil, e
	}
	var textHeader mail.InlineHeader
	textHeader.Set("Content-Type", "text/plain; charset=utf-8")
	part, e := w.CreateInline()
	if e != nil {
		return nil, nil, e
	}
	body, e := part.CreatePart(textHeader)
	if e != nil {
		return nil, nil, e
	}
	if _, e = io.WriteString(body, o.Text); e != nil {
		return nil, nil, e
	}
	body.Close()
	part.Close()
	for _, att := range o.Attachments {
		var header mail.AttachmentHeader
		header.Set("Content-Type", "application/octet-stream")
		header.SetFilename(att.Name)
		writer, e := w.CreateAttachment(header)
		if e != nil {
			return nil, nil, e
		}
		if _, e = writer.Write(att.Data); e != nil {
			return nil, nil, e
		}
		writer.Close()
	}
	if e = w.Close(); e != nil {
		return nil, nil, e
	}
	addresses := []string{}
	for _, list := range [][]*stdmail.Address{to, cc, bcc} {
		for _, a := range list {
			addresses = append(addresses, a.Address)
		}
	}
	return b.Bytes(), addresses, nil
}

type loginAuth struct {
	user, password string
	step           int
}

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) { return "LOGIN", nil, nil }
func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	if a.step == 1 {
		return []byte(a.user), nil
	}
	if a.step == 2 {
		return []byte(a.password), nil
	}
	return nil, errors.New("SMTP认证失败")
}

var smtpSubmit = func(ctx context.Context, acc Account, secret string, o Outgoing) error {
	data, addresses, e := buildOutgoing(o, acc)
	if e != nil {
		return e
	}
	host, ok := smtpHosts[acc.Provider]
	if !ok {
		return errors.New("不支持此邮箱的SMTP发信")
	}
	server := strings.Split(host, ":")[0]
	conn, e := dialProxy(ctx, host)
	if e != nil {
		return errors.New("SMTP连接失败，请检查部署网络或邮箱代理")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: server, MinVersion: tls.VersionTLS12})
	if e = tlsConn.HandshakeContext(ctx); e != nil {
		return errors.New("SMTP加密连接失败")
	}
	client, e := smtp.NewClient(tlsConn, server)
	if e != nil {
		return errors.New("SMTP握手失败")
	}
	defer client.Close()
	supported, methods := client.Extension("AUTH")
	if !supported {
		return errors.New("SMTP服务器未提供认证")
	}
	var auth smtp.Auth = &loginAuth{user: acc.Email, password: secret}
	if strings.Contains(strings.ToUpper(methods), "PLAIN") {
		auth = smtp.PlainAuth("", acc.Email, secret, server)
	}
	if e = client.Auth(auth); e != nil {
		return errors.New("SMTP登录失败，请检查授权码及SMTP服务开关")
	}
	if e = client.Mail(acc.Email); e != nil {
		return errors.New("SMTP拒绝发件人")
	}
	for _, to := range addresses {
		if e = client.Rcpt(to); e != nil {
			return errors.New("SMTP拒绝收件人，邮件未提交")
		}
	}
	writer, e := client.Data()
	if e != nil {
		return errors.New("SMTP暂不接受邮件正文")
	}
	if _, e = writer.Write(data); e != nil {
		return errors.New("发信结果不确定，请检查原邮箱记录后再决定是否重发")
	}
	if e = writer.Close(); e != nil {
		return errors.New("发信结果不确定，请检查原邮箱记录后再决定是否重发")
	}
	_ = client.Quit()
	return nil
}

func graphSend(ctx context.Context, token string, o Outgoing) error {
	to, cc, bcc, e := validateOutgoing(o)
	if e != nil {
		return e
	}
	convert := func(list []*stdmail.Address) []map[string]any {
		out := []map[string]any{}
		for _, a := range list {
			out = append(out, map[string]any{"emailAddress": map[string]string{"address": a.Address, "name": a.Name}})
		}
		return out
	}
	atts := []map[string]any{}
	size := 0
	for _, att := range o.Attachments {
		size += len(att.Data)
		atts = append(atts, map[string]any{"@odata.type": "#microsoft.graph.fileAttachment", "name": att.Name, "contentType": "application/octet-stream", "contentBytes": att.Data})
	}
	if size > 2<<20 {
		return errors.New("Outlook附件合计最多2MB")
	}
	payload := map[string]any{"message": map[string]any{"subject": o.Subject, "body": map[string]string{"contentType": "Text", "content": o.Text}, "toRecipients": convert(to), "ccRecipients": convert(cc), "bccRecipients": convert(bcc), "attachments": atts}, "saveToSentItems": true}
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://graph.microsoft.com/v1.0/me/sendMail", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, e := requestHTTP(ctx).Do(req)
	if e != nil {
		return errors.New("发信结果不确定，请检查原邮箱记录后再决定是否重发")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 {
		return errors.New("Outlook需要Mail.Send权限，请重新授权微软账户")
	}
	if resp.StatusCode != 202 {
		return errors.New("微软未接受邮件，请检查授权和收件人")
	}
	return nil
}
func (a *App) sendMail(w http.ResponseWriter, r *http.Request) {
	var o Outgoing
	if !decode(w, r, &o) {
		return
	}
	if _, _, _, e := validateOutgoing(o); e != nil {
		fail(w, 400, e.Error())
		return
	}
	acc, ok := findAccount(a.store.snapshot(), o.AccountID)
	if !ok || !acc.Authorized {
		fail(w, 400, "请选择已授权的发件邮箱")
		return
	}
	if !a.engine.claim("send:" + o.ID) {
		fail(w, 409, "发信正在处理或系统繁忙，请稍后查看记录")
		return
	}
	defer a.engine.release("send:" + o.ID)
	claimed := false
	err := a.store.update(func(st *State) error {
		for _, record := range st.Sent {
			if record.ID == o.ID {
				return nil
			}
		}
		st.Sent = append(st.Sent, SendRecord{ID: o.ID, AccountID: acc.ID, To: o.To, Subject: o.Subject, Time: time.Now().Unix(), Status: "submitting"})
		if len(st.Sent) > 200 {
			st.Sent = st.Sent[len(st.Sent)-200:]
		}
		claimed = true
		return nil
	})
	if err != nil {
		fail(w, 500, "发信记录无法保存，邮件未发送")
		return
	}
	if !claimed {
		jsonOut(w, 200, map[string]string{"status": "alreadySubmitted"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	ctx, err = accountContext(ctx, a.store, acc)
	secret, e := a.store.decrypt(acc.Secret)
	if err == nil {
		err = e
	}
	if err == nil {
		if acc.Provider == "outlook" {
			var tok msTokens
			tok, err = refreshMS(ctx, acc, secret)
			if err == nil {
				data, _ := json.Marshal(tok)
				err = a.store.update(func(st *State) error {
					for i, v := range st.Accounts {
						if v.ID == acc.ID && v.Generation == acc.Generation {
							st.Accounts[i].Secret = a.store.encrypt(string(data))
						}
					}
					return nil
				})
				if err == nil {
					err = graphSend(ctx, tok.Access, o)
				}
			}
		} else {
			err = smtpSubmit(ctx, acc, secret, o)
		}
	}
	_ = a.store.update(func(st *State) error {
		for i, v := range st.Sent {
			if v.ID == o.ID {
				if err == nil {
					st.Sent[i].Status = "accepted"
				} else {
					st.Sent[i].Status = "checkRequired"
				}
				break
			}
		}
		event(st, "send", "发信请求已处理，请在发信记录查看状态")
		return nil
	})
	if err != nil {
		fail(w, 502, err.Error())
		return
	}
	jsonOut(w, 202, map[string]string{"status": "accepted"})
}
