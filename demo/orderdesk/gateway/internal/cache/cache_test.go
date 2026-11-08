package cache

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestWithCacheServesSecondHitFromMemory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	calls := 0
	engine.GET("/x", WithCache(60, func(c *gin.Context) {
		calls++
		c.String(http.StatusOK, "hello")
	}))

	for i := 0; i < 3; i++ {
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/x", nil))
	}

	if calls != 1 {
		t.Fatalf("expected 1 upstream call, got %d", calls)
	}
}
