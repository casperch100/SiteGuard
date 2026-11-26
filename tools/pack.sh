#!/bin/sh
# 打包上架用的 zip：只放擴充功能執行需要的檔案。
# 用法：sh tools/pack.sh   → dist/site-guard-<version>.zip
set -e
cd "$(dirname "$0")/.."
VERSION=$(ruby -rjson -e 'print JSON.parse(File.read("manifest.json"))["version"]')
mkdir -p dist
OUT="dist/site-guard-$VERSION.zip"
rm -f "$OUT"
zip -qrX "$OUT" manifest.json icons src -x '*.DS_Store'
echo "$OUT"
