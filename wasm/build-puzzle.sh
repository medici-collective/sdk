#!/bin/bash

rm -rf pkg/
wasm-pack build --release --target nodejs --scope puzzlehq --out-dir pkg/node-wasm -- --features "serial" --no-default-features
cd pkg/node-wasm
sed -i '' 's/aleo-wasm/aleo-wasm-nodejs/g' package.json
npm publish
cd ../..
RUSTFLAGS='-C link-arg=--max-memory=4294967296' wasm-pack build --release --target web --scope puzzlehq --out-dir pkg/web-wasm
cd pkg/web-wasm
sed -i '' 's/aleo-wasm/aleo-wasm-web/g' package.json
jq '.files += ["snippets/"]' package.json > temp.json && mv temp.json package.json
npm publish --access public
cd ../..
