package main

import (
        "bytes"
        "context"
        "crypto/sha256"
        "crypto/tls"
        "crypto/x509"
        "encoding/hex"
        "flag"
        "github.com/hashicorp/yamux"
        "github.com/nicocha30/ligolo-ng/pkg/agent"
        "github.com/nicocha30/ligolo-ng/pkg/utils/selfcert"
        "github.com/sirupsen/logrus"
        goproxy "golang.org/x/net/proxy"
        "net"
        "net/http"
        "net/url"
        "nhooyr.io/websocket"
        "strings"
        "time"
)

var (
        version = "dev"
        commit  = "none"
        date    = "unknown"
)

func main() {
        var tlsConfig tls.Config
        var ignoreCertificate = flag.Bool("ignore-cert", false, "ignore TLS certificate validation (dangerous), only for debug purposes")
        var acceptFingerprint = flag.String("accept-fingerprint", "", "accept certificates matching the following SHA256 fingerprint (hex format)")
        var verbose = flag.Bool("v", false, "enable verbose mode")
        var retry = flag.Bool("retry", false, "auto-retry on error")
        var socksProxy = flag.String("proxy", "", "proxy URL address (http://admin:secret@127.0.0.1:8080)"+
                " or socks://admin:secret@127.0.0.1:8080")
        var serverAddr = flag.String("connect", "", "connect to proxy (domain:port)")
        var bindAddr = flag.String("bind", "", "bind to ip:port")
        var userAgent = flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "+
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36", "HTTP User-Agent")
        var versionFlag = flag.Bool("version", false, "show the current version")

        flag.Usage = func() {
                flag.PrintDefaults()
        }

        flag.Parse()

        if *versionFlag {
                return
        }

        logrus.SetReportCaller(*verbose)

        if *verbose {
                logrus.SetLevel(logrus.DebugLevel)
        }

        if *bindAddr != "" {
                selfcrt := selfcert.NewSelfCert(nil)
                crt, err := selfcrt.GetCertificate(*bindAddr)
                if err != nil {
                        logrus.Fatal(err)
                }
                tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
                        return crt, nil
                }
                lis, err := net.Listen("tcp", *bindAddr)
                if err != nil {
                        logrus.Fatal(err)
                }
                for {
                        conn, err := lis.Accept()
                        if err != nil {
                                logrus.Error(err)
                                continue
                        }
                        tlsConn := tls.Server(conn, &tlsConfig)

                        if err := connect(tlsConn); err != nil {
                                logrus.Error(err)
                        }
                }
        }

        if *serverAddr == "" {
        }

        serverUrl, err := url.Parse(*serverAddr)
        if err == nil && serverUrl != nil {
                if serverUrl.Scheme == "https" {
                        //websocket https connection
                        tlsConfig.ServerName = serverUrl.Hostname()
                }
        } else {
                //direct connection. try to parse as host:port
                host, _, err := net.SplitHostPort(*serverAddr)
                if err != nil {
                }
                tlsConfig.ServerName = host
        }

        if *ignoreCertificate {
                tlsConfig.InsecureSkipVerify = true
        }

        var conn net.Conn

        for {
                var err error
                if serverUrl != nil && serverUrl.Scheme == "https" {
                        *serverAddr = strings.Replace(*serverAddr, "https://", "wss://", 1)
                        //websocket
                        err = wsconnect(&tlsConfig, *serverAddr, *socksProxy, *userAgent)
                } else {
                        if *socksProxy != "" {
                                //suppose that scheme is socks:// or socks5://
                                var proxyUrl *url.URL
                                proxyUrl, err = url.Parse(*socksProxy)
                                if err != nil {
                                }
                                if proxyUrl.Scheme == "http" {
                                }
                                if proxyUrl.Scheme == "socks" || proxyUrl.Scheme == "socks5" {
                                        pass, _ := proxyUrl.User.Password()
                                        conn, err = sockDial(*serverAddr, proxyUrl.Host, proxyUrl.User.Username(), pass)
                                } else {
                                }
                        } else {
                                conn, err = net.Dial("tcp", *serverAddr)
                        }
                        if err == nil {
                                if *acceptFingerprint != "" {
                                        tlsConfig.InsecureSkipVerify = true
                                        tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
                                                crtFingerprint := sha256.Sum256(rawCerts[0])
                                                crtMatch, err := hex.DecodeString(*acceptFingerprint)
                                                if err != nil {
                                                }
                                                if bytes.Compare(crtMatch, crtFingerprint[:]) != 0 {
                                                }
                                                return nil
                                        }
                                }
                                tlsConn := tls.Client(conn, &tlsConfig)

                                err = connect(tlsConn)
                        }
                }

                if *retry {
                        time.Sleep(5 * time.Second)
                } else {
                        logrus.Fatal(err)
                }
        }
}

func sockDial(serverAddr string, socksProxy string, socksUser string, socksPass string) (net.Conn, error) {
        proxyDialer, err := goproxy.SOCKS5("tcp", socksProxy, &goproxy.Auth{
                User:     socksUser,
                Password: socksPass,
        }, goproxy.Direct)
        if err != nil {
        }
        return proxyDialer.Dial("tcp", serverAddr)
}

func connect(conn net.Conn) error {
        yamuxConn, err := yamux.Server(conn, yamux.DefaultConfig())
        if err != nil {
                return err
        }

        logrus.WithFields(logrus.Fields{"addr": conn.RemoteAddr()}).Info("Connection established")

        for {
                conn, err := yamuxConn.Accept()
                if err != nil {
                        return err
                }
                go agent.HandleConn(conn)
        }
}

func wsconnect(config *tls.Config, wsaddr string, proxystr string, useragent string) error {

        //timeout for websocket library connection - 20 seconds
        ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
        defer cancel()

        //in case of websocket proxy can be http with login:pass
        //Ex: proxystr = "http://admin:secret@127.0.0.1:8080"
        proxyUrl, err := url.Parse(proxystr)
        if err != nil || proxystr == "" {
                proxyUrl = nil
        }

        httpTransport := &http.Transport{}
        config.MinVersion = tls.VersionTLS10

        httpTransport = &http.Transport{
                MaxIdleConns:    http.DefaultMaxIdleConnsPerHost,
                TLSClientConfig: config,
                Proxy:           http.ProxyURL(proxyUrl),
        }

        httpClient := &http.Client{Transport: httpTransport}
        httpheader := &http.Header{}
        httpheader.Add("User-Agent", useragent)

        wsConn, _, err := websocket.Dial(ctx, wsaddr, &websocket.DialOptions{HTTPClient: httpClient, HTTPHeader: *httpheader})
        if err != nil {
                return err
        }

        //timeout for netconn derived from websocket connection - it must be very big
        netctx, cancel := context.WithTimeout(context.Background(), time.Hour*999999)
        netConn := websocket.NetConn(netctx, wsConn, websocket.MessageBinary)
        defer cancel()
        yamuxConn, err := yamux.Server(netConn, yamux.DefaultConfig())
        if err != nil {
                return err
        }

        for {
                conn, err := yamuxConn.Accept()
                if err != nil {
                        return err
                }
                go agent.HandleConn(conn)
        }
}
