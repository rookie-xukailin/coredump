#!/usr/bin/env bash
# 检查 core 文件的架构、notes、程序头 —— 用法: probe_core.sh <core>
set -u
F="$1"
echo "### file:"
file "$F"
echo "### notes (readelf -n):"
readelf -n "$F" 2>&1 | head -40
echo "### program headers (readelf -lW):"
readelf -lW "$F" 2>&1 | head -30
