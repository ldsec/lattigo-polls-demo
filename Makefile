main.wasm:
	GOOS=js GOARCH=wasm go build -o server/static/client.wasm client/client.go

server/static/wasm_exec.js:
	cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .

ALL: client.wasm