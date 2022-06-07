.DEFAULT_GOAL := all

GOROOT=$(shell go env GOROOT)

main.wasm:
	GOOS=js GOARCH=wasm go build -o server/static/client.wasm client/client.go

server/static/wasm_exec.js:
	cp "$(GOROOT)/misc/wasm/wasm_exec.js" server/static/wasm_exec.js

all: server/static/wasm_exec.js client.wasm