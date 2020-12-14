# Lattigo-polls-demo

This is a demo program for the [Lattigo](https://github.com/ldsec/lattigo) homomorphic encryption library.

It consist in a web-application for scheduling meetings, where the poll-result is computed homomorphically.

The both the server and client are implemented with the `github.com/ldsec/lattigo` library.
In order to run on the client's web-browser, the client-side code is compiled in WebAssembly and is fetched by the client web-browser on page load.

## Running the server

The following sequence of command will download the source-code, compile the client application and start the server.

```
git clone https://github.com/ldsec/lattigo-polls-demo
cd lattigo-polls-demo
make
cd server
go run server.go
```


