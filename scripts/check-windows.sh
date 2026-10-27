#!/usr/bin/env bash
# Comprueba desde Linux que el código #[cfg(windows)] compila (sin enlazar).
# ring necesita un compilador C para el target; sin mingw-w64 usamos clang con
# cabeceras mínimas generadas al vuelo. Uso: scripts/check-windows.sh [check|clippy]
set -euo pipefail
cd "$(dirname "$0")/.."
inc=$(mktemp -d); trap 'rm -rf "$inc"' EXIT
printf '#pragma once\n#define assert(x) ((void)0)\n#define static_assert _Static_assert\n' > "$inc/assert.h"
printf '#pragma once\n#include <stddef.h>\nvoid *memcpy(void*,const void*,size_t);void *memset(void*,int,size_t);int memcmp(const void*,const void*,size_t);void *memmove(void*,const void*,size_t);\n' > "$inc/string.h"
export CC_x86_64_pc_windows_gnu=clang
export AR_x86_64_pc_windows_gnu=llvm-ar
export CFLAGS_x86_64_pc_windows_gnu="--target=x86_64-w64-mingw32 -ffreestanding -I$inc"
cargo "${1:-check}" --target x86_64-pc-windows-gnu
