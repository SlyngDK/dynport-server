package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-http-utils/headers"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"
)

type Replication struct {
	l     *zap.Logger
	g     *gin.Engine
	store *DataStore

	client     http.Client
	listenAddr string
	peers      []string
	secret     string
	listeners  []func()
}

func NewReplication(l *zap.Logger, store *DataStore, listenAddr, secret string, peers []string) *Replication {
	gin.SetMode("release")
	g := gin.New()
	g.Use(ginzapWithRecovery(l, zapcore.DebugLevel))

	g.Use(gin.BasicAuth(map[string]string{
		"repl": secret,
	}))

	client := http.Client{
		Timeout: 5 * time.Second,
	}
	return &Replication{l: l, g: g, store: store, client: client, listenAddr: listenAddr, peers: peers, secret: secret}
}

func (r *Replication) Start() {
	if r.listenAddr == "" {
		r.l.Info("replication is not enabled")
		return
	}
	r.setupHandlers()
	go func() {
		err := r.g.Run(r.listenAddr)
		if err != nil {
			r.l.With(zap.Error(err)).Error("failed to start gin")
		}
	}()
}

func (r *Replication) RegisterUpdateListener(fn func()) {
	r.listeners = append(r.listeners, fn)
}

func (r *Replication) sendUpdate() {
	for _, fn := range r.listeners {
		go fn()
	}
}

func (r *Replication) RunFullSync() {
	if r.listenAddr == "" {
		return
	}
	for _, peer := range r.peers {
		u := fmt.Sprintf("http://%s/leases", peer)
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			r.l.With(zap.Error(err), zap.String("url.origin", u)).Warn("failed to create request for getting leases")
			continue
		}
		req.Header.Set(headers.Accept, "application/json")
		req.SetBasicAuth("repl", r.secret)

		response, err := r.client.Do(req)
		if err != nil {
			r.l.With(zap.Error(err), zap.String("url.origin", u)).Warn("failed to get leases")
			continue
		}
		defer response.Body.Close()

		if response.StatusCode != 200 {
			r.l.With(zap.String("url.origin", u)).Warn("unexpected response status code")
			continue
		}
		var leases []PortMappingLease
		err = json.NewDecoder(response.Body).Decode(&leases)
		if err != nil {
			r.l.With(zap.Error(err), zap.String("url.origin", u)).Warn("failed to get leases")
			continue
		}
		for _, lease := range leases {
			err := r.store.UpsertLease(&lease)
			if err != nil {
				r.l.With(zap.Error(err), zap.String("url.origin", u)).Warn("failed to upsert lease")
				continue
			}
		}
	}
	r.sendUpdate()
}

func (r *Replication) setupHandlers() {
	g := r.g
	g.GET("/leases", func(c *gin.Context) {
		leases, err := r.store.GetLeases()
		if err != nil {
			c.Error(err)
			c.AbortWithStatus(500)
			return
		}

		c.JSON(200, leases)
	})
	g.PUT("/leases/:id", func(c *gin.Context) {
		if !strings.HasPrefix(c.ContentType(), "application/json") {
			c.AbortWithStatus(400)
			return
		}

		var lease PortMappingLease

		err := c.BindJSON(&lease)
		if err != nil {
			r.l.With(zap.Error(err)).Warn("failed to parse body to lease")
			c.AbortWithStatus(400)
			return
		}

		err = r.store.UpsertLease(&lease)
		if err != nil {
			r.l.With(zap.Error(err)).Warn("failed to update lease")
			c.AbortWithStatus(500)
			return
		}
		r.sendUpdate()
	})
}

func (r *Replication) PortMappingLeaseListener(lease PortMappingLease) {
	if r.listenAddr == "" {
		return
	}
	r.l.Sugar().Debug("received update for lease %s", lease.Id)
	jsonBytes, err := json.Marshal(lease)
	if err != nil {
		r.l.With(zap.Error(err)).Warn("failed to marshal lease")
		return
	}

	for _, peer := range r.peers {

		u := fmt.Sprintf("http://%s/leases/%s", peer, lease.Id)
		req, err := http.NewRequest("PUT", u, bytes.NewReader(jsonBytes))
		if err != nil {
			r.l.With(zap.Error(err), zap.String("url.origin", u)).Warn("failed to create request for putting lease")
			continue
		}
		req.Header.Set(headers.ContentType, "application/json")
		req.SetBasicAuth("repl", r.secret)

		response, err := r.client.Do(req)
		if err != nil {
			r.l.With(zap.Error(err), zap.String("url.origin", u)).Warn("failed to put lease")
			continue
		}
		defer response.Body.Close()

		if response.StatusCode != 200 {
			r.l.With(zap.String("url.origin", u), zap.Int("http.response.status_code", response.StatusCode)).
				Warn("unexpected response status code")
			continue
		}
	}
}

func ginzapWithRecovery(logger *zap.Logger, accessLogLevel zapcore.Level) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		defer func() {
			end := time.Now()
			latency := end.Sub(start)

			fields := []zapcore.Field{
				zap.Int("http.response.status_code", c.Writer.Status()),
				zap.String("http.request.method", c.Request.Method),
				zap.String("url.path", c.Request.URL.Path),
				zap.String("url.query", c.Request.URL.RawQuery),
				zap.String("client.ip", c.ClientIP()),
				zap.String("user_agent.original", c.Request.UserAgent()),
				zap.Duration("event.duration", latency),
			}

			if err := recover(); err != nil {

				c.Status(500)
				fields = append(fields, zap.String("error.message", fmt.Sprint(err)))
				fields = append(fields, zap.Int("http.response.status_code", c.Writer.Status()))

				// Check for a broken connection, as it is not really a
				// condition that warrants a panic stack trace.
				var brokenPipe bool
				if ne, ok := err.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") || strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				if brokenPipe {
					logger.With(fields...).Error(c.Request.URL.Path)
					// If the connection is dead, we can't write a status to it.
					c.Error(err.(error)) // nolint: errcheck
					c.AbortWithStatus(500)
					return
				}

				fields = append(fields, zap.String("error.stack_trace", string(debug.Stack())))
			}

			if len(c.Errors) > 0 {
				// Append error field if this is an erroneous request.
				for _, e := range c.Errors.Errors() {
					logger.With(fields...).Error(e)
				}
			} else {
				logger.With(fields...).Log(accessLogLevel, c.Request.URL.Path)
			}
		}()
		c.Next()
	}
}
