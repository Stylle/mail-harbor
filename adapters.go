package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	imapid "github.com/emersion/go-imap-id"
	"github.com/emersion/go-imap/client"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
	"golang.org/x/net/html"
)

var providerHosts = map[string]string{"qq": "imap.qq.com:993", "163": "imap.163.com:993", "gmail": "imap.gmail.com:993"}
var imapDial = func(ctx context.Context, host string) (net.Conn, error) {
	dial := tls.Dialer{NetDialer: &net.Dialer{Timeout: 12 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: strings.Split(host, ":")[0]}}
	return dial.DialContext(ctx, "tcp", host)
}

const maxMailBytes = 20 << 20

type Attachment struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	Size  int    `json:"size"`
}
type Detail struct {
	Text        string       `json:"text"`
	Attachments []Attachment `json:"attachments"`
}
type fetchedMail struct {
	Detail
	files map[int][]byte
}

func imapConnect(ctx context.Context, a Account, secret string) (*client.Client, error) {
	host, ok := providerHosts[a.Provider]
	if !ok {
		return nil, errors.New("不支持的邮箱类型")
	}
	conn, e := imapDial(ctx, host)
	if e != nil {
		return nil, errors.New("无法连接邮箱服务器，请检查部署网络")
	}
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	c, e := client.New(conn)
	if e != nil {
		conn.Close()
		return nil, errors.New("邮箱服务器握手失败")
	}
	c.Timeout = 20 * time.Second
	c.ErrorLog = log.New(io.Discard, "", 0)
	if e = c.Login(a.Email, secret); e != nil {
		c.Terminate()
		return nil, errors.New("邮箱登录失败，请检查邮箱地址、IMAP开关及客户端授权码")
	}
	// NetEase requires an identifying ID on some accounts before SELECT.
	if yes, _ := c.Support("ID"); yes {
		if _, e = imapid.NewClient(c).ID(imapid.ID{"name": "Mail Harbor", "version": version, "vendor": "Mail Harbor"}); e != nil {
			c.Terminate()
			return nil, errors.New("邮箱客户端身份协商失败")
		}
	}
	return c, nil
}
func imapHeaders(ctx context.Context, a Account, secret string) ([]Message, Account, error) {
	c, e := imapConnect(ctx, a, secret)
	if e != nil {
		return nil, a, e
	}
	defer c.Terminate()
	box, e := c.Select("INBOX", true)
	if e != nil {
		return nil, a, errors.New("收件箱访问被拒绝，请检查IMAP授权")
	}
	reset := a.UIDValidity != box.UidValidity
	a.UIDValidity = box.UidValidity
	if reset {
		a.LastUID = 0
		a.Initialized = false
	}
	if box.Messages == 0 {
		a.Initialized = true
		return nil, a, nil
	}
	set := new(imap.SeqSet)
	uid := a.Initialized
	previousUID := a.LastUID
	if uid {
		if box.UidNext > 0 && a.LastUID >= box.UidNext-1 {
			return nil, a, nil
		}
		criteria := imap.NewSearchCriteria()
		criteria.Uid = new(imap.SeqSet)
		criteria.Uid.AddRange(a.LastUID+1, 0)
		uids, err := c.UidSearch(criteria)
		if err != nil {
			return nil, a, errors.New("增量邮件索引读取失败")
		}
		sort.Slice(uids, func(i, j int) bool { return uids[i] < uids[j] })
		count := 0
		for _, n := range uids {
			if n > previousUID {
				set.AddNum(n)
				count++
				if count == 100 {
					break
				}
			}
		}
		if count == 0 {
			return nil, a, nil
		}
	} else {
		start := uint32(1)
		if box.Messages > 30 {
			start = box.Messages - 29
		}
		set.AddRange(start, box.Messages)
	}
	ch := make(chan *imap.Message, 32)
	done := make(chan error, 1)
	go func() {
		items := []imap.FetchItem{imap.FetchUid, imap.FetchEnvelope, imap.FetchFlags, imap.FetchRFC822Size, imap.FetchBodyStructure}
		if uid {
			done <- c.UidFetch(set, items, ch)
		} else {
			done <- c.Fetch(set, items, ch)
		}
	}()
	out := []Message{}
	for m := range ch {
		if m == nil || m.Envelope == nil || m.Uid == 0 {
			continue
		}
		if uid && m.Uid <= previousUID {
			continue
		}
		from, sender := "", ""
		if len(m.Envelope.From) > 0 {
			f := m.Envelope.From[0]
			from = f.PersonalName
			sender = f.Address()
			if from == "" {
				from = sender
			}
		}
		read := false
		for _, f := range m.Flags {
			if f == imap.SeenFlag {
				read = true
			}
		}
		out = append(out, Message{ID: fmt.Sprintf("%s:%d:%d", a.ID, box.UidValidity, m.Uid), AccountID: a.ID, RemoteID: strconv.FormatUint(uint64(m.Uid), 10), Subject: m.Envelope.Subject, From: from, Sender: sender, Date: m.Envelope.Date.Unix(), Read: read, Size: m.Size, Attachments: hasAttachments(m.BodyStructure)})
		if m.Uid > a.LastUID {
			a.LastUID = m.Uid
		}
		if len(out) >= 500 {
			c.Terminate()
			return nil, a, errors.New("新邮件积压超过单次上限，请暂停通知后重新接入邮箱")
		}
	}
	if e = <-done; e != nil {
		return nil, a, errors.New("邮件列表读取失败，稍后重试")
	}
	a.Initialized = true
	return out, a, nil
}
func hasAttachments(body *imap.BodyStructure) bool {
	if body == nil {
		return false
	}
	if strings.EqualFold(body.Disposition, "attachment") {
		return true
	}
	for _, part := range body.Parts {
		if hasAttachments(part) {
			return true
		}
	}
	return hasAttachments(body.BodyStructure)
}
func imapDetail(ctx context.Context, a Account, secret string, m Message) (fetchedMail, error) {
	var out fetchedMail
	c, e := imapConnect(ctx, a, secret)
	if e != nil {
		return out, e
	}
	defer c.Terminate()
	box, e := c.Select("INBOX", true)
	if e != nil {
		return out, errors.New("无法打开收件箱")
	}
	if box.UidValidity != a.UIDValidity {
		return out, errors.New("邮箱索引已变化，请同步后重新打开")
	}
	if m.Size > maxMailBytes {
		return out, errors.New("邮件超过20MB读取上限，请前往原邮箱查看")
	}
	uid, e := strconv.ParseUint(m.RemoteID, 10, 32)
	if e != nil {
		return out, e
	}
	set := new(imap.SeqSet)
	set.AddNum(uint32(uid))
	section := &imap.BodySectionName{Peek: true}
	ch := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(set, []imap.FetchItem{section.FetchItem()}, ch) }()
	var raw []byte
	for msg := range ch {
		r := msg.GetBody(section)
		if r != nil {
			raw, e = io.ReadAll(io.LimitReader(r, maxMailBytes+1))
			if e != nil || len(raw) > maxMailBytes {
				c.Terminate()
				return out, errors.New("邮件超出读取上限")
			}
		}
	}
	if e = <-done; e != nil || len(raw) == 0 {
		return out, errors.New("邮件不存在、已移动或暂时无法读取")
	}
	return parseMail(raw)
}
func plainHTML(s string) string {
	root, e := html.Parse(strings.NewReader(s))
	if e != nil {
		return ""
	}
	var b strings.Builder
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "head") {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		if n.Type == html.ElementNode && (n.Data == "br" || n.Data == "p" || n.Data == "div" || n.Data == "tr") {
			b.WriteByte('\n')
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(root)
	return strings.TrimSpace(b.String())
}
func parseMail(raw []byte) (fetchedMail, error) {
	out := fetchedMail{Detail: Detail{Attachments: []Attachment{}}, files: map[int][]byte{}}
	r, e := mail.CreateReader(strings.NewReader(string(raw)))
	if e != nil && r == nil {
		return out, errors.New("邮件格式无法解析")
	}
	defer r.Close()
	htmlBody := ""
	for i := 0; i < 150; i++ {
		part, e := r.NextPart()
		if e == io.EOF {
			break
		}
		if part == nil {
			return out, errors.New("邮件编码无法解析")
		}
		data, e := io.ReadAll(io.LimitReader(part.Body, maxMailBytes+1))
		if e != nil || len(data) > maxMailBytes {
			return out, errors.New("邮件内容过大")
		}
		switch h := part.Header.(type) {
		case *mail.InlineHeader:
			typ, _, _ := h.ContentType()
			if typ == "text/plain" {
				out.Text += string(data) + "\n"
			} else if typ == "text/html" {
				htmlBody += string(data)
			}
		case *mail.AttachmentHeader:
			name, _ := h.Filename()
			if name == "" {
				name = "attachment"
			}
			out.Attachments = append(out.Attachments, Attachment{i, name, len(data)})
			out.files[i] = data
		}
	}
	if strings.TrimSpace(out.Text) == "" {
		out.Text = plainHTML(htmlBody)
	}
	if len(out.Text) > 1<<20 {
		out.Text = out.Text[:1<<20] + "\n[正文显示已截断]"
	}
	return out, nil
}

type msTokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Expires int64  `json:"expires_in"`
	Until   int64  `json:"until"`
	Error   string `json:"error"`
}

var externalHTTP = &http.Client{Timeout: 35 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return errors.New("redirect refused") }}

func formJSON(ctx context.Context, endpoint string, values url.Values, out any) error {
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(values.Encode()))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := externalHTTP.Do(req)
	if e != nil {
		return errors.New("授权服务器不可达，请检查部署网络")
	}
	defer resp.Body.Close()
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); e != nil {
		return errors.New("授权服务返回无效响应")
	}
	return nil
}

const msBase = "https://login.microsoftonline.com/consumers/oauth2/v2.0/"

func refreshMS(ctx context.Context, a Account, secret string) (msTokens, error) {
	var tok msTokens
	if json.Unmarshal([]byte(secret), &tok) != nil || tok.Refresh == "" {
		return tok, errors.New("请先完成微软账号授权")
	}
	if tok.Until > time.Now().Unix()+90 && tok.Access != "" {
		return tok, nil
	}
	old := tok.Refresh
	var next msTokens
	e := formJSON(ctx, msBase+"token", url.Values{"client_id": {a.ClientID}, "grant_type": {"refresh_token"}, "refresh_token": {old}, "scope": {"offline_access https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read"}}, &next)
	if e != nil {
		return tok, e
	}
	if next.Access == "" || next.Error != "" {
		return tok, errors.New("微软授权已过期或被撤销，请重新授权")
	}
	if next.Refresh == "" {
		next.Refresh = old
	}
	next.Until = time.Now().Unix() + next.Expires
	return next, nil
}
func graphGet(ctx context.Context, token, endpoint string, out any) error {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host != "graph.microsoft.com" || !strings.HasPrefix(u.Path, "/v1.0/me/") {
		return errors.New("无效的微软同步地址")
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Prefer", `outlook.body-content-type="text", IdType="ImmutableId"`)
	resp, e := externalHTTP.Do(req)
	if e != nil {
		return errors.New("无法连接Microsoft Graph")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 410 {
		return errors.New("微软同步游标已过期，请重新接入邮箱以建立索引")
	}
	if resp.StatusCode == 429 {
		return errors.New("微软接口限流，请稍后同步")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("微软邮件接口返回HTTP %d，请检查授权", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 25<<20)).Decode(out)
}

type graphMessage struct {
	ID          string    `json:"id"`
	Subject     string    `json:"subject"`
	Date        time.Time `json:"receivedDateTime"`
	Read        bool      `json:"isRead"`
	Attachments bool      `json:"hasAttachments"`
	Preview     string    `json:"bodyPreview"`
	From        struct {
		Address struct {
			Name  string `json:"name"`
			Email string `json:"address"`
		} `json:"emailAddress"`
	} `json:"from"`
	Body struct {
		Content string `json:"content"`
		Type    string `json:"contentType"`
	} `json:"body"`
	Removed json.RawMessage `json:"@removed"`
}

func graphHeaders(ctx context.Context, a Account, token string) ([]Message, Account, error) {
	endpoint := a.Cursor
	if endpoint == "" {
		endpoint = "https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages/delta?$select=id,subject,from,receivedDateTime,isRead,hasAttachments,bodyPreview&$filter=" + url.QueryEscape("receivedDateTime ge "+time.Now().UTC().AddDate(0, 0, -7).Format(time.RFC3339))
	}
	out := []Message{}
	for page := 0; page < 10; page++ {
		var batch struct {
			Items []graphMessage `json:"value"`
			Next  string         `json:"@odata.nextLink"`
			Delta string         `json:"@odata.deltaLink"`
		}
		if e := graphGet(ctx, token, endpoint, &batch); e != nil {
			return nil, a, e
		}
		for _, m := range batch.Items {
			if len(m.Removed) > 0 {
				continue
			}
			out = append(out, Message{ID: a.ID + ":" + m.ID, AccountID: a.ID, RemoteID: m.ID, Subject: m.Subject, From: m.From.Address.Name, Sender: m.From.Address.Email, Date: m.Date.Unix(), Read: m.Read, Attachments: m.Attachments, Preview: m.Preview})
		}
		if batch.Next != "" {
			endpoint = batch.Next
			a.Cursor = endpoint
			continue
		}
		if batch.Delta == "" {
			return nil, a, errors.New("微软接口未提供同步游标")
		}
		a.Cursor = batch.Delta
		a.Initialized = true
		break
	}
	return out, a, nil
}
func graphDetail(ctx context.Context, token string, m Message) (fetchedMail, error) {
	out := fetchedMail{Detail: Detail{Attachments: []Attachment{}}, files: map[int][]byte{}}
	var gm graphMessage
	endpoint := "https://graph.microsoft.com/v1.0/me/messages/" + url.PathEscape(m.RemoteID)
	if e := graphGet(ctx, token, endpoint+"?$select=body", &gm); e != nil {
		return out, e
	}
	out.Text = gm.Body.Content
	if strings.EqualFold(gm.Body.Type, "html") {
		out.Text = plainHTML(out.Text)
	}
	if m.Attachments {
		var batch struct {
			Items []struct {
				Type   string `json:"@odata.type"`
				Name   string `json:"name"`
				Size   int    `json:"size"`
				Data   []byte `json:"contentBytes"`
				Inline bool   `json:"isInline"`
			} `json:"value"`
		}
		if e := graphGet(ctx, token, endpoint+"/attachments", &batch); e != nil {
			return out, e
		}
		total := 0
		for i, att := range batch.Items {
			if att.Inline || att.Type != "#microsoft.graph.fileAttachment" {
				continue
			}
			total += att.Size
			if total > maxMailBytes {
				return out, errors.New("附件总计超过20MB，请前往原邮箱下载")
			}
			out.Attachments = append(out.Attachments, Attachment{i, att.Name, att.Size})
			out.files[i] = att.Data
		}
	}
	if len(out.Text) > 1<<20 {
		out.Text = out.Text[:1<<20] + "\n[正文显示已截断]"
	}
	return out, nil
}
