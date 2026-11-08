package router

import (
	"github.com/gin-gonic/gin"

	"github.com/orderdesk/gateway/internal/auth"
	"github.com/orderdesk/gateway/internal/cache"
	"github.com/orderdesk/gateway/internal/config"
	"github.com/orderdesk/gateway/internal/metrics"
	"github.com/orderdesk/gateway/internal/proxy"
)

func New(cfg config.Config) *gin.Engine {
	engine := gin.Default()
	engine.Use(auth.Middleware(cfg.JWTSecret))

	engine.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	engine.GET("/metrics", gin.WrapH(metrics.Handler()))
	engine.GET("/api/orders", cache.WithCache(120, proxy.Forward(cfg.Upstream)))
	engine.Any("/api/*path", proxy.Forward(cfg.Upstream))

	return engine
}
