import io
import os
import struct
import unittest
from unittest import mock

from memtaskman.models import (
    GGUFError,
    describe_model,
    looks_like_model,
    ollama_url,
    parse_ollama_ps,
    read_gguf_header,
)


def s(text: str, v1: bool = False) -> bytes:
    b = text.encode()
    return (struct.pack("<I", len(b)) if v1 else struct.pack("<Q", len(b))) + b


def kv_str(key, val, v1=False):
    return s(key, v1) + struct.pack("<I", 8) + s(val, v1)


def kv_u32(key, val, v1=False):
    return s(key, v1) + struct.pack("<I", 4) + struct.pack("<I", val)


def kv_str_array(key, items):
    return s(key) + struct.pack("<I", 9) + struct.pack("<I", 8) + struct.pack("<Q", len(items)) + b"".join(s(i) for i in items)


def kv_f32_array(key, n):
    return s(key) + struct.pack("<I", 9) + struct.pack("<I", 6) + struct.pack("<Q", n) + b"\0" * 4 * n


def gguf(kvs: list[bytes], version=3, v1=False) -> io.BytesIO:
    if v1:
        head = b"GGUF" + struct.pack("<I", 1) + struct.pack("<I", 7) + struct.pack("<I", len(kvs))
    else:
        head = b"GGUF" + struct.pack("<I", version) + struct.pack("<Q", 291) + struct.pack("<Q", len(kvs))
    return io.BytesIO(head + b"".join(kvs) + b"\xff" * 64)  # trailing bytes stand in for tensor data


class GGUFTests(unittest.TestCase):
    def test_v3_header_with_tokenizer_before_file_type(self):
        f = gguf([
            kv_str("general.architecture", "qwen3"),
            kv_str("general.name", "Qwen3 14B"),
            kv_str_array("tokenizer.ggml.tokens", ["a", "bb", "ccc"] * 1000),
            kv_f32_array("tokenizer.ggml.scores", 3000),
            kv_u32("general.file_type", 15),
            kv_str("never.read", "x"),
        ])
        meta = read_gguf_header(f)
        self.assertEqual(meta["version"], 3)
        self.assertEqual(meta["tensor_count"], 291)
        self.assertEqual(meta["general.file_type"], 15)
        self.assertNotIn("never.read", meta)
        self.assertEqual(describe_model(meta), "Qwen3 14B Q4_K_M")

    def test_stops_early_and_never_reads_weights(self):
        f = gguf([kv_str("general.architecture", "llama"), kv_u32("general.file_type", 7),
                  kv_str_array("tokenizer.ggml.tokens", ["t"] * 50000)])
        meta = read_gguf_header(f)
        self.assertLess(f.tell(), 200)  # stopped before the 50k-entry vocabulary
        self.assertEqual(describe_model(meta), "llama Q8_0")

    def test_v1_32bit_counts(self):
        f = gguf([kv_str("general.architecture", "llama", v1=True), kv_u32("general.file_type", 2, v1=True)], v1=True)
        meta = read_gguf_header(f)
        self.assertEqual((meta["version"], meta["general.file_type"]), (1, 2))

    def test_rejects_non_gguf_and_truncated(self):
        with self.assertRaises(GGUFError):
            read_gguf_header(io.BytesIO(b"PK\x03\x04" + b"\0" * 64))
        with self.assertRaises(GGUFError):
            read_gguf_header(io.BytesIO(b"GGUF" + struct.pack("<I", 3) + b"\0\0"))

    def test_read_limit(self):
        f = gguf([kv_str_array("tokenizer.ggml.tokens", ["x" * 100] * 100)])
        with self.assertRaises(GGUFError):
            read_gguf_header(f, limit=1000)

    def test_describe_unknown_type_and_size_label(self):
        self.assertEqual(describe_model({"general.architecture": "gpt-oss", "general.file_type": 99}), "gpt-oss type 99")
        self.assertEqual(describe_model({"general.name": "Mistral", "general.size_label": "7B",
                                         "general.architecture": "llama", "general.file_type": 1}),
                         "Mistral 7B F16 (llama)")

    def test_looks_like_model(self):
        self.assertTrue(looks_like_model(r"D:\models\phi-3.Q4_K_M.gguf"))
        self.assertTrue(looks_like_model("/home/u/.ollama/models/blobs/sha256-" + "a" * 64))
        self.assertFalse(looks_like_model(r"C:\Windows\System32\ntdll.dll"))


class OllamaTests(unittest.TestCase):
    def test_parse_ps(self):
        data = {"models": [{"name": "qwen3:14b", "size": 10 * 2**30, "size_vram": 6 * 2**30,
                            "details": {"parameter_size": "14.8B", "quantization_level": "Q4_K_M"},
                            "context_length": 8192}]}
        m = parse_ollama_ps(data)[0]
        self.assertEqual(m["ram"], 4 * 2**30)
        self.assertEqual((m["params"], m["quant"], m["context"]), ("14.8B", "Q4_K_M", 8192))
        self.assertEqual(parse_ollama_ps({"models": []}), [])
        self.assertIsNone(parse_ollama_ps({"models": [{"name": "x"}]})[0]["ram"])

    def test_url_from_env(self):
        cases = {None: "http://127.0.0.1:11434/api/ps", "0.0.0.0": "http://127.0.0.1:11434/api/ps",
                 "http://localhost:9999/": "http://localhost:9999/api/ps", "127.0.0.1:8080": "http://127.0.0.1:8080/api/ps"}
        for env, want in cases.items():
            with mock.patch.dict(os.environ, {} if env is None else {"OLLAMA_HOST": env}, clear=False):
                if env is None:
                    os.environ.pop("OLLAMA_HOST", None)
                self.assertEqual(ollama_url(), want)

    def test_remote_host_is_never_queried(self):
        from memtaskman.models import ollama_loaded

        with mock.patch.dict(os.environ, {"OLLAMA_HOST": "10.0.0.5:11434"}):
            models, why = ollama_loaded()
        self.assertIsNone(models)
        self.assertIn("only localhost", why)


if __name__ == "__main__":
    unittest.main()
