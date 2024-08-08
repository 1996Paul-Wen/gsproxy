package gsproxy

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/op/go-logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/lo"
)

var servLogger = logging.MustGetLogger("Server")

// Server 代理服务
type Server struct {
	listener          net.Listener
	addr              string
	exposeMetricsAddr string   // prometheus监控指标的暴露地址，如":9090"
	credentials       []string // basic auth的用户名密码
	blackDomains      []string

	activeConnMetrics prometheus.Gauge
}

// NewServer create a proxy server
func NewServer(addr, exposeMetricsAddr string, credentials []string, genCredential bool, blackDomains []string) *Server {
	if genCredential {
		credentials = append(credentials, RandStringBytesMaskImprSrc(16)+":"+
			RandStringBytesMaskImprSrc(16))
		servLogger.Infof("gen credentials %s for auth\n", credentials[len(credentials)-1])
	}
	for i, credential := range credentials {
		servLogger.Info(credential)
		credentials[i] = base64.StdEncoding.EncodeToString([]byte(credential))
	}
	return &Server{addr: addr, exposeMetricsAddr: exposeMetricsAddr, credentials: credentials, blackDomains: blackDomains}
}

// Start a proxy server
func (s *Server) Start() {
	// 如果 `exposeMetricsAddr` 不为空，则设置 Prometheus 监控
	if s.exposeMetricsAddr != "" {
		// 创建一个新的 Prometheus 注册表
		reg := prometheus.NewRegistry()
		// 注册 Go 运行时指标收集器
		reg.MustRegister(collectors.NewGoCollector(
			collectors.WithGoCollectorRuntimeMetrics(collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile("/.*")}),
		))
		// 定义并注册一个新的 Gauge 类型的指标，用于记录活动连接数
		s.activeConnMetrics = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "gsproxy",
			Subsystem: "server",
			Name:      "active_connection",
		})
		reg.MustRegister(s.activeConnMetrics)
		// 启动一个旁路的 HTTP 服务，用于暴露 Prometheus 监控指标
		go func() {
			// Expose the registered metrics via HTTP.
			http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
			servLogger.Infof("expose metrics listen in %s\n", s.exposeMetricsAddr)
			if err := http.ListenAndServe(s.exposeMetricsAddr, nil); err != nil {
				servLogger.Error(err)
			}
		}()
	}

	var err error
	s.listener, err = net.Listen("tcp", s.addr)
	if err != nil {
		servLogger.Fatal(err)
	}

	servLogger.Infof("proxy listen in %s, waiting for connection...\n", s.addr)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			servLogger.Error(err)
			continue
		}
		go s.newConn(conn).serve()
	}
}

// newConn create a conn to serve client request
func (s *Server) newConn(rwc net.Conn) *conn {
	return &conn{
		server: s,
		rwc:    rwc,
		brc:    bufio.NewReader(rwc),
	}
}

// isAuth return weather the client should be authenticate
func (s *Server) isAuth() bool {
	return len(s.credentials) > 0
}

// validateCredentials parse "Basic basic-credentials" and validate it
func (s *Server) validateCredential(basicCredential string) bool {
	c := strings.Split(basicCredential, " ")
	if len(c) == 2 && strings.EqualFold(c[0], "Basic") && lo.Contains(s.credentials, c[1]) {
		return true
	}
	return false
}

func (s *Server) shouldProxy(domain string) bool {
	for _, blackDomain := range s.blackDomains {
		if matchPattern(blackDomain, domain) {
			return false
		}
	}
	return true
}

// matchPattern checks whether a string matches a pattern
func matchPattern(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	matched, _ := filepath.Match(pattern, s)
	return matched
}
