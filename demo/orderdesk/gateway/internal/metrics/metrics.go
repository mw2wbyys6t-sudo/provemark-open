package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var requests = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "orderdesk",
		Name:      "gateway_requests_total",
		Help:      "Total requests handled by the gateway.",
	},
	[]string{"route", "status"},
)

func init() {
	prometheus.MustRegister(requests)
}

func Handler() http.Handler {
	return promhttp.Handler()
}

func Observe(route, status string) {
	requests.WithLabelValues(route, status).Inc()
	fmt.Println("observed", route, status)
}
