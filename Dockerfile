# 多阶段构建：用静态编译的 Go 二进制产出最小运行镜像，不依赖 CGO。
FROM golang:1.23-alpine AS build
WORKDIR /src

# 先拷贝依赖描述以利用层缓存（本项目仅依赖标准库，无第三方包）。
COPY go.mod ./
RUN go mod download

COPY . .
# CGO_ENABLED=0 产出静态二进制；-trimpath 与 -ldflags 让镜像可复现、更精简。
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/crcsrv ./cmd/crcsrv

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/crcsrv /crcsrv
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/crcsrv"]
