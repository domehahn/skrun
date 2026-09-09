FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/skrun ./cmd/skrun

FROM alpine:3.21
RUN apk add --no-cache bubblewrap ca-certificates
COPY --from=build /out/skrun /usr/local/bin/skrun
RUN adduser -D -u 65532 skrun
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/skrun"]
