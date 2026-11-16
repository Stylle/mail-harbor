package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

type proxyKey struct{}

func validateProxy(raw string) error {
	if raw == "" {
		return nil
	}
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2000 || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return errors.New("代理地址需要使用 http://、https:// 或 socks5://")
	}
	return nil
}
func accountContext(ctx context.Context, s *Store, a Account) (context.Context, error) {
	plain, e := s.decrypt(a.Proxy)
	if e != nil {
		return ctx, errors.New("代理配置不可读取")
	}
	if e = validateProxy(plain); e != nil {
		return ctx, e
	}
	return context.WithValue(ctx, proxyKey{}, plain), nil
}
func requestHTTP(ctx context.Context) *http.Client {
	raw, _ := ctx.Value(proxyKey{}).(string)
	if raw == "" {
		return externalHTTP
	}
	u, _ := url.Parse(raw)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(u)
	transport.DisableKeepAlives = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{Timeout: 35 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}
func dialProxy(ctx context.Context, target string) (net.Conn, error) {
	raw, _ := ctx.Value(proxyKey{}).(string)
	dialer := &net.Dialer{Timeout: 12 * time.Second}
	if raw == "" {
		return dialer.DialContext(ctx, "tcp", target)
	}
	if e := validateProxy(raw); e != nil {
		return nil, e
	}
	u, _ := url.Parse(raw)
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
		if u.Scheme == "socks5" {
			port = "1080"
		}
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	if u.Scheme == "socks5" {
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, e := proxy.SOCKS5("tcp", addr, auth, dialer)
		if e != nil {
			return nil, errors.New("SOCKS5代理配置无效")
		}
		conn, e := d.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
		if e != nil {
			return nil, errors.New("SOCKS5代理连接失败")
		}
		return conn, nil
	}
	conn, e := dialer.DialContext(ctx, "tcp", addr)
	if e != nil {
		return nil, errors.New("HTTP代理连接失败")
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if e = tlsConn.HandshakeContext(ctx); e != nil {
			conn.Close()
			return nil, errors.New("HTTPS代理证书或连接失败")
		}
		conn = tlsConn
	}
	req := &http.Request{Method: "CONNECT", URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if u.User != nil {
		pw, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pw)))
	}
	if e = req.Write(conn); e != nil {
		conn.Close()
		return nil, errors.New("代理隧道建立失败")
	}
	response, e := http.ReadResponse(bufio.NewReaderSize(conn, 4096), req)
	if e != nil || response.StatusCode != 200 {
		conn.Close()
		return nil, errors.New("代理拒绝CONNECT隧道，请检查地址和认证")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
func proxyDisplay(raw string) string {
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	u.User = nil
	return strings.TrimSuffix(u.String(), "/")
}
