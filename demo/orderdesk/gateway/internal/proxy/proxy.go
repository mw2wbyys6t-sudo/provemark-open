package proxy

import (
	"io"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// Forward relays the incoming request to the upstream API and copies the
// response back to the caller.
func Forward(upstream string) gin.HandlerFunc {
	return func(c *gin.Context) {
		target, err := url.Parse(upstream + c.Request.URL.RequestURI())
		if err != nil {
			c.AbortWithStatus(http.StatusBadGateway)
			return
		}

		request, err := http.NewRequest(c.Request.Method, target.String(), c.Request.Body)
		if err != nil {
			c.AbortWithStatus(http.StatusBadGateway)
			return
		}
		request.Header = c.Request.Header

		response, err := http.DefaultClient.Do(request)
		if err != nil {
			c.AbortWithStatus(http.StatusBadGateway)
			return
		}
		defer response.Body.Close()

		io.Copy(c.Writer, response.Body)
	}
}

// FetchURL follows a user-supplied preview link.
func FetchURL(raw string) ([]byte, error) {
	response, err := http.Get(raw)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}
