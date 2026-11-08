package cache

import (
	"bytes"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type entry struct {
	body      []byte
	expiresAt time.Time
}

type store struct {
	mu      sync.RWMutex
	items   map[string]entry
	ttl     time.Duration
}

func WithCache(seconds int, next gin.HandlerFunc) gin.HandlerFunc {
	s := &store{items: map[string]entry{}, ttl: time.Duration(seconds) * time.Second}

	return func(c *gin.Context) {
		key := c.Request.URL.RequestURI()

		s.mu.RLock()
		cached, ok := s.items[key]
		s.mu.RUnlock()

		if ok && time.Now().Before(cached.expiresAt) {
			c.Writer.Write(cached.body)
			return
		}

		recorder := &bufferedWriter{ResponseWriter: c.Writer}
		c.Writer = recorder
		next(c)

		s.mu.Lock()
		s.items[key] = entry{body: recorder.buffer.Bytes(), expiresAt: time.Now().Add(s.ttl)}
		s.mu.Unlock()
	}
}

type bufferedWriter struct {
	gin.ResponseWriter
	buffer bytes.Buffer
}

func (w *bufferedWriter) Write(p []byte) (int, error) {
	w.buffer.Write(p)
	return w.ResponseWriter.Write(p)
}
