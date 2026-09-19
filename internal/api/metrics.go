package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// metrics 是进程内最小指标注册表，以 Prometheus 文本 exposition 格式暴露，
// 不引入第三方依赖。计数器与直方图用原子操作/分片桶更新，并发安全，
// 且只记录聚合计数，绝不保存任何请求数据，不影响无状态语义。
type metricsRegistry struct {
	requestsTotal *counterVec
	errorsTotal   *counterVec
	duration      *histogramVec
	inFlight      atomic.Int64
}

type counterVec struct {
	mu       sync.Mutex
	name     string
	help     string
	labels   []string
	counters map[string]*atomic.Int64
}

func newCounterVec(name, help string, labels ...string) *counterVec {
	return &counterVec{name: name, help: help, labels: labels, counters: map[string]*atomic.Int64{}}
}

func (c *counterVec) inc(labelValues ...string) {
	key := strings.Join(labelValues, "|")
	c.mu.Lock()
	ctr, ok := c.counters[key]
	if !ok {
		ctr = &atomic.Int64{}
		c.counters[key] = ctr
	}
	c.mu.Unlock()
	ctr.Add(1)
}

type histogramVec struct {
	mu      sync.Mutex
	name    string
	help    string
	labels  []string
	buckets []float64
	values  map[string]*histogramValue
}

type histogramValue struct {
	counts []atomic.Int64
	sum    atomic.Int64 // 微秒求和，渲染时换算为秒
	total  atomic.Int64
}

func newHistogramVec(name, help string, buckets []float64, labels ...string) *histogramVec {
	return &histogramVec{name: name, help: help, labels: labels, buckets: buckets, values: map[string]*histogramValue{}}
}

func (h *histogramVec) observe(seconds float64, labelValues ...string) {
	key := strings.Join(labelValues, "|")
	h.mu.Lock()
	hv, ok := h.values[key]
	if !ok {
		hv = &histogramValue{counts: make([]atomic.Int64, len(h.buckets)+1)}
		h.values[key] = hv
	}
	h.mu.Unlock()
	us := int64(seconds * 1e6)
	hv.sum.Add(us)
	hv.total.Add(1)
	for i, ub := range h.buckets {
		if seconds <= ub {
			hv.counts[i].Add(1)
		}
	}
	hv.counts[len(h.buckets)].Add(1) // +Inf
}

func newMetrics() *metricsRegistry {
	return &metricsRegistry{
		requestsTotal: newCounterVec("crc_http_requests_total",
			"Total HTTP requests handled.", "route", "method", "status"),
		errorsTotal: newCounterVec("crc_http_errors_total",
			"Total structured error responses by code.", "route", "code"),
		duration: newHistogramVec("crc_http_request_duration_seconds",
			"HTTP request latency in seconds.",
			[]float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
			"route"),
	}
}

// statusRecorder 捕获写出的状态码与结构化错误码供指标记录。
type statusRecorder struct {
	http.ResponseWriter
	status  int
	errCode string
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// metricsMiddleware 记录路由、状态码、错误类型与耗时。
func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		s.metrics.inFlight.Add(1)
		next.ServeHTTP(rec, r)
		s.metrics.inFlight.Add(-1)

		route := routeName(r)
		elapsed := time.Since(start).Seconds()
		s.metrics.requestsTotal.inc(route, r.Method, fmt.Sprintf("%d", rec.status))
		s.metrics.duration.observe(elapsed, route)
		if rec.status >= 400 {
			code := rec.errCode
			if code == "" {
				code = "UNCLASSIFIED"
			}
			s.metrics.errorsTotal.inc(route, code)
		}
	})
}

// routeName 归并路径，避免把任意未知路径打成高基数标签。
func routeName(r *http.Request) string {
	switch {
	case r.URL.Path == "/healthz":
		return "/healthz"
	case r.URL.Path == "/metrics":
		return "/metrics"
	case r.URL.Path == "/api/v1/profiles":
		return "/api/v1/profiles"
	case r.URL.Path == "/api/v1/vectors":
		return "/api/v1/vectors"
	case r.URL.Path == "/api/v1/checksums":
		return "/api/v1/checksums"
	case r.URL.Path == "/api/v1/checksums/batch":
		return "/api/v1/checksums/batch"
	case r.URL.Path == "/api/v1/stream":
		return "/api/v1/stream"
	case r.URL.Path == "/api/v1/verify":
		return "/api/v1/verify"
	default:
		return "unmatched"
	}
}

// escapeLabelValue 转义 Prometheus 标签值中的反斜杠/引号/换行。
func escapeLabelValue(v string) string {
	replacer := strings.NewReplacer("\\", `\\`, "\n", `\n`, "\"", `\"`)
	return replacer.Replace(v)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, ErrMethodNotAllowed, "use GET")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	var b strings.Builder

	renderCounter := func(c *counterVec) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
		c.mu.Lock()
		keys := make([]string, 0, len(c.counters))
		for k := range c.counters {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vals := strings.Split(k, "|")
			b.WriteString(c.name)
			b.WriteString("{")
			for i, lv := range c.labels {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `%s="%s"`, lv, escapeLabelValue(vals[i]))
			}
			fmt.Fprintf(&b, "} %d\n", c.counters[k].Load())
		}
		c.mu.Unlock()
	}

	renderCounter(s.metrics.requestsTotal)
	renderCounter(s.metrics.errorsTotal)

	fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s histogram\n",
		s.metrics.duration.name, s.metrics.duration.help, s.metrics.duration.name)
	h := s.metrics.duration
	h.mu.Lock()
	keys := make([]string, 0, len(h.values))
	for k := range h.values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		hv := h.values[k]
		vals := strings.Split(k, "|")
		baseLabels := ""
		if len(h.labels) > 0 {
			parts := make([]string, len(h.labels))
			for i, ln := range h.labels {
				parts[i] = fmt.Sprintf(`%s="%s"`, ln, escapeLabelValue(vals[i]))
			}
			baseLabels = strings.Join(parts, ",")
		}
		bucketLine := func(le string, count int64) {
			labels := baseLabels
			if labels != "" {
				labels += ","
			}
			fmt.Fprintf(&b, "%s_bucket{%sle=\"%s\"} %d\n", h.name, labels, le, count)
		}
		// observe 对每个上界 >= 观测值的桶都计数，因此 counts 本身即累计值。
		for i, ub := range h.buckets {
			bucketLine(strconvFormatFloat(ub), hv.counts[i].Load())
		}
		bucketLine("+Inf", hv.total.Load())
		suffix := ""
		if baseLabels != "" {
			suffix = "{" + baseLabels + "}"
		}
		fmt.Fprintf(&b, "%s_sum%s %g\n", h.name, suffix, float64(hv.sum.Load())/1e6)
		fmt.Fprintf(&b, "%s_count%s %d\n", h.name, suffix, hv.total.Load())
	}
	h.mu.Unlock()

	fmt.Fprintf(&b, "# HELP crc_requests_in_flight Current number of in-flight requests.\n")
	fmt.Fprintf(&b, "# TYPE crc_requests_in_flight gauge\n")
	fmt.Fprintf(&b, "crc_requests_in_flight %d\n", s.metrics.inFlight.Load())

	_, _ = w.Write([]byte(b.String()))
}

// strconvFormatFloat 以 Prometheus 习惯的紧凑形式渲染桶上界。
func strconvFormatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}
