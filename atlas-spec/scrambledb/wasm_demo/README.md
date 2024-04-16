# Prerequisites

Building the demo requires the [`emscripten` toolchain](https://emscripten.org/) to be installed.

# Running the demo

At the `scrambledb` crate root, run the following to build the WASM
version of the project in `./pkg`:

```shell
$ CC=emcc AR=emar wasm-pack build --target web --features wasm
```

To serve the project locally, copy `index.html` to the right directory
and start e.g. a simple Python web server there:

```shell
$ cp ./wasm_demo/index.html ./pkg/
$ cd ./pkg
$ python -m http.server
```
