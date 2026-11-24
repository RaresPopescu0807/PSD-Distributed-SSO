# One Dockerfile for all services; choose the binary with --build-arg APP=<name>.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG APP
RUN CGO_ENABLED=0 go build -o /app ./services/${APP}

FROM alpine:3.22
COPY --from=build /app /app
USER nobody
ENTRYPOINT ["/app"]
