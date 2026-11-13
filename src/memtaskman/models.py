"""AI model RAM accounting: GGUF headers and the Ollama API.

CPU inference and partial GPU offload keep model weights in system RAM, usually
memory-mapped, so they appear under "Mapped files" in the inspector. This module
names those files (from the GGUF header only, never the weights) and asks a running
Ollama server how each loaded model is split between RAM and VRAM.

Rules (same spirit as gputaskman): GET requests only, to localhost only, only when an
Ollama process is running; short timeout, capped response; nothing is ever sent
except the request line.
"""

from __future__ import annotations

import json
import os
import struct
import urllib.request
from typing import BinaryIO

GGUF_MAGIC = b"GGUF"
MAX_HEADER_BYTES = 32 * 1024 * 1024  # tokenizer arrays can be several MB; never read weights
WANTED = ("general.name", "general.architecture", "general.file_type", "general.size_label",
          "general.basename", "general.quantization_version")

# llama.cpp's llama_ftype values (general.file_type)
FILE_TYPES = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 7: "Q8_0", 8: "Q5_0", 9: "Q5_1", 10: "Q2_K",
    11: "Q3_K_S", 12: "Q3_K_M", 13: "Q3_K_L", 14: "Q4_K_S", 15: "Q4_K_M", 16: "Q5_K_S", 17: "Q5_K_M",
    18: "Q6_K", 19: "IQ2_XXS", 20: "IQ2_XS", 21: "Q2_K_S", 22: "IQ3_XS", 23: "IQ3_XXS", 24: "IQ1_S",
    25: "IQ4_NL", 26: "IQ3_S", 27: "IQ3_M", 28: "IQ2_S", 29: "IQ2_M", 30: "IQ4_XS", 31: "IQ1_M", 32: "BF16", 36: "TQ1_0", 37: "TQ2_0", 38: "MXFP4_MOE",
}

# GGUF value types -> struct format (fixed-size scalars)
_SCALARS = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
_STRING, _ARRAY = 8, 9


class GGUFError(ValueError):
    pass


class _Reader:
    def __init__(self, f: BinaryIO, limit: int):
        self.f = f
        self.limit = limit

    def read(self, n: int) -> bytes:
        if self.f.tell() + n > self.limit:
            raise GGUFError("header larger than the read limit")
        b = self.f.read(n)
        if len(b) != n:
            raise GGUFError("truncated header")
        return b

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def string(self, count64: bool) -> bytes:
        n = self.u64() if count64 else self.u32()
        return self.read(n)

    def skip(self, n: int) -> None:
        if self.f.tell() + n > self.limit:
            raise GGUFError("header larger than the read limit")
        self.f.seek(n, os.SEEK_CUR)


def _value(r: _Reader, vtype: int, count64: bool, keep: bool):
    if vtype in _SCALARS:
        fmt = "<" + _SCALARS[vtype]
        return struct.unpack(fmt, r.read(struct.calcsize(fmt)))[0]
    if vtype == _STRING:
        s = r.string(count64)
        return s.decode("utf-8", errors="replace") if keep else None
    if vtype == _ARRAY:
        etype = r.u32()
        n = r.u64() if count64 else r.u32()
        if etype in _SCALARS:
            r.skip(struct.calcsize("<" + _SCALARS[etype]) * n)
        else:
            for _ in range(n):  # arrays of strings (tokenizer vocab) or nested arrays
                _value(r, etype, count64, False)
        return f"<array of {n}>"
    raise GGUFError(f"unknown value type {vtype}")


def read_gguf_header(f: BinaryIO, limit: int = MAX_HEADER_BYTES) -> dict:
    """Metadata from a GGUF file's header. Reads keys until the wanted ones are found."""
    r = _Reader(f, limit)
    if r.read(4) != GGUF_MAGIC:
        raise GGUFError("not a GGUF file")
    version = r.u32()
    count64 = version >= 2  # v1 used 32-bit counts and string lengths
    tensors = r.u64() if count64 else r.u32()
    kv_count = r.u64() if count64 else r.u32()
    meta: dict = {"version": version, "tensor_count": tensors}
    for _ in range(kv_count):
        key = r.string(count64).decode("utf-8", errors="replace")
        vtype = r.u32()
        keep = key in WANTED
        val = _value(r, vtype, count64, keep)
        if keep:
            meta[key] = val
        if "general.architecture" in meta and "general.file_type" in meta:
            break  # enough to describe it; don't walk the tokenizer vocabulary
    return meta


_cache: dict[tuple[str, int, float], dict | None] = {}


def gguf_info(path: str) -> dict | None:
    """Header metadata plus file size, or None when the file is not a readable GGUF. Cached per file version."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    key = (path, st.st_size, st.st_mtime)
    if key not in _cache:
        _cache[key] = _read_info(path)
    return _cache[key]


def _read_info(path: str) -> dict | None:
    try:
        with open(path, "rb") as f:
            meta = read_gguf_header(f)
        meta["file_size"] = os.path.getsize(path)
        return meta
    except (OSError, GGUFError, struct.error):
        return None


def describe_model(meta: dict) -> str:
    name = meta.get("general.name") or meta.get("general.basename") or meta.get("general.architecture") or "model"
    bits = [name]
    label = meta.get("general.size_label")
    if label and str(label).lower() not in name.lower():
        bits.append(label)
    ft = meta.get("general.file_type")
    if ft is not None:
        bits.append(FILE_TYPES.get(ft, f"type {ft}"))
    arch = meta.get("general.architecture")
    if arch and arch.lower() not in name.lower():
        bits.append(f"({arch})")
    return " ".join(str(b) for b in bits)


def looks_like_model(path: str) -> bool:
    """GGUF by extension, or an Ollama blob (sha256-<hex>, no extension)."""
    base = os.path.basename(path).lower()
    return base.endswith(".gguf") or (base.startswith("sha256-") and "." not in base)


# ---------------------------------------------------------------------- Ollama


def ollama_url() -> str:
    host = os.environ.get("OLLAMA_HOST", "127.0.0.1:11434").strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.rstrip("/")
    if host.startswith("0.0.0.0"):
        host = "127.0.0.1" + host[len("0.0.0.0"):]
    if ":" not in host:
        host += ":11434"
    return f"http://{host}/api/ps"


def parse_ollama_ps(data: dict) -> list[dict]:
    out = []
    for m in data.get("models", []) or []:
        size = m.get("size")
        vram = m.get("size_vram")
        details = m.get("details") or {}
        out.append({
            "name": m.get("name") or m.get("model"),
            "size": size,
            "vram": vram,
            "ram": size - vram if isinstance(size, int) and isinstance(vram, int) else None,
            "params": details.get("parameter_size"),
            "quant": details.get("quantization_level"),
            "context": m.get("context_length"),
        })
    return out


def ollama_loaded(timeout: float = 0.5, cap: int = 1 << 20) -> tuple[list[dict] | None, str | None]:
    """(models, reason if unavailable). Localhost GET only."""
    url = ollama_url()
    host = url.split("//", 1)[1].split("/", 1)[0].split(":")[0]
    if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        return None, f"OLLAMA_HOST points at {host}; only localhost is queried"
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "memtaskman"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never via a proxy
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(cap + 1)
        if len(body) > cap:
            return None, "response too large"
        return parse_ollama_ps(json.loads(body)), None
    except (OSError, ValueError) as e:
        return None, f"Ollama API not reachable ({type(e).__name__})"
