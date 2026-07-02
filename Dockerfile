FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/clph-web ./cmd/clph-web

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/clph-web /usr/local/bin/clph-web
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/clph-web"]
