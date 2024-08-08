package gsproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"strings"

	"github.com/op/go-logging"
)

var connLogger = logging.MustGetLogger("Conn")

type conn struct {
	rwc    net.Conn
	brc    *bufio.Reader
	server *Server
}

// serve tunnel the client connection to remote host. 核心代理逻辑
func (c *conn) serve() {
	defer c.rwc.Close()
	rawHttpRequestHeader, remote, credential, isHttps, err := c.getTunnelInfo()
	if err != nil {
		connLogger.Error(err)
		return
	}

	if !c.auth(credential) {
		connLogger.Error("Auth fail: " + credential)
		return
	}

	if !c.server.shouldProxy(strings.Split(remote, ":")[0]) {
		connLogger.Error("domain is in black list: " + remote)
		_, err = c.rwc.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		if err != nil {
			connLogger.Error(err)
		}
		return
	}

	connLogger.Info("connecting to " + remote)
	remoteConn, err := net.Dial("tcp", remote)
	if err != nil {
		connLogger.Error(err)
		return
	}

	if isHttps {
		// if https, should sent 200 to client
		_, err = c.rwc.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			connLogger.Error(err)
			return
		}
	} else {
		// if not https, should sent the request header to remote
		// 在应用层解析到的请求头需要通过remoteConn发往目标服务器
		_, err = rawHttpRequestHeader.WriteTo(remoteConn)
		if err != nil {
			connLogger.Error(err)
			return
		}
	}

	// build bidirectional-streams
	connLogger.Info("begin tunnel", c.rwc.RemoteAddr(), "<->", remote)
	c.tunnel(remoteConn)
	connLogger.Info("stop tunnel", c.rwc.RemoteAddr(), "<->", remote)
}

// getClientInfo parse client request header to get some information:
func (c *conn) getTunnelInfo() (rawReqHeader bytes.Buffer, host, credential string, isHttps bool, err error) {
	tp := textproto.NewReader(c.brc)

	// First line: GET /index.html HTTP/1.0
	var requestLine string
	if requestLine, err = tp.ReadLine(); err != nil {
		return
	}

	method, requestURI, _, ok := parseRequestLine(requestLine)
	if !ok {
		err = &BadRequestError{"malformed HTTP request"}
		return
	}

	// https request
	if method == "CONNECT" {
		isHttps = true
		requestURI = "http://" + requestURI
		// note that a CONNECT Request has no body
	}

	// get remote host
	uriInfo, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return
	}

	credential = mimeHeader.Get("Proxy-Authorization")

	if uriInfo.Host == "" {
		host = mimeHeader.Get("Host")
	} else {
		if !strings.Contains(uriInfo.Host, ":") {
			host = uriInfo.Host + ":80"
		} else {
			host = uriInfo.Host
		}
	}

	// rebuild http request header
	rawReqHeader.WriteString(requestLine + "\r\n")
	for k, vs := range mimeHeader {
		for _, v := range vs {
			rawReqHeader.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}
	rawReqHeader.WriteString("\r\n")
	return
}

// auth provide basic authentication
func (c *conn) auth(credential string) bool {
	if !c.server.isAuth() || c.server.validateCredential(credential) {
		return true
	}
	// 407
	_, err := c.rwc.Write(
		[]byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"*\"\r\n\r\n"))
	if err != nil {
		connLogger.Error(err)
	}
	return false
}

// tunnel http message between client and server
func (c *conn) tunnel(remoteConn net.Conn) {
	if c.server.activeConnMetrics != nil {
		c.server.activeConnMetrics.Inc()
		defer func() {
			c.server.activeConnMetrics.Dec()
		}()
	}
	go func() {
		// `c.brc` 是一个 `bufio.Reader`，它从 `c.rwc` 读取数据。
		// `rawHttpRequestHeader` 在 `getTunnelInfo`方法中已经被读取

		// here tunnel the TCP connection to the desired destination, the proxy works at the transport layer
		// - 如果是代理非https请求，在`serve`方法中`rawHttpRequestHeader`已经被发送到 `remoteConn`，此时`c.brc` 中的数据是 HTTP 请求的 body 部分，然后在这里被发送到 `remoteConn`
		// - 如果是代理https请求，直接转发tcp stream
		_, err := c.brc.WriteTo(remoteConn)
		if err != nil {
			connLogger.Warning(err)
		}
		remoteConn.Close()
	}()
	_, err := io.Copy(c.rwc, remoteConn)
	if err != nil {
		connLogger.Warning(err)
	}
}

func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}

// BadRequestError 非法的请求
type BadRequestError struct {
	what string
}

func (b *BadRequestError) Error() string {
	return b.what
}
