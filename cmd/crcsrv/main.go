// Command crcsrv 启动可独立部署的 CRC 核算 HTTP 服务。
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"crcservice/internal/api"
)

func main() {
	addr := os.Getenv("CRC_LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	// -healthcheck-uri 供容器健康检查使用：二进制自身发起一次 GET，
	// 返回 200 即以退出码 0 结束，避免在 distroless 镜像里依赖 shell/curl。
	healthURI := flag.String("healthcheck-uri", "",
		"if set, GET this URI once and exit 0 on HTTP 200 (container healthcheck mode)")
	flag.Parse()

	if *healthURI != "" {
		os.Exit(runHealthcheck(*healthURI))
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewServer().Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// 优雅关停：收到 SIGINT/SIGTERM 后拒绝新请求并给在途请求留 10s。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("crc-service %s listening on %s", api.Version, addr)
		if !api.StateKeyConfigured() {
			log.Printf("CRC_STATE_KEY not set: stream state tokens use a random per-process key " +
				"and will not survive restart or work across instances")
		}
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutdown signal received")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("graceful shutdown failed: %v", err)
	}
	log.Printf("server stopped")
}

// runHealthcheck 执行一次性容器自检：3 秒超时内拿到 2xx 即健康。
func runHealthcheck(uri string) int {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(uri)
	if err != nil {
		log.Printf("healthcheck failed: %v", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("healthcheck got status %d", resp.StatusCode)
		return 1
	}
	return 0
}
