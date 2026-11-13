import unittest

from memtaskman.model import HINT
from memtaskman.runtime import detect, stem


class RuntimeDetectTests(unittest.TestCase):
    def test_stem(self):
        self.assertEqual(stem(r"C:\Program Files\App\Chrome.EXE"), "chrome")
        self.assertEqual(stem("/usr/bin/node"), "node")

    def test_chrome_renderer(self):
        r = detect("chrome.exe", ["chrome_elf.dll", "ntdll.dll"], ["chrome.exe", "--type=renderer"])
        self.assertEqual((r.name, r.detail), ("Chrome", "renderer"))

    def test_chromium_utility_subtype(self):
        r = detect("msedge.exe", [], ["msedge.exe", "--type=utility", "--utility-sub-type=network.mojom.NetworkService"])
        self.assertEqual(r.name, "Edge")
        self.assertEqual(r.detail, "utility:network")

    def test_electron_app_gpu(self):
        r = detect("Discord.exe", [], ["Discord.exe", "--type=gpu-process"])
        self.assertEqual((r.name, r.detail), ("Electron", "gpu"))

    def test_browser_main_process_without_flags(self):
        r = detect("brave.exe", ["chrome.dll"], ["brave.exe"])
        self.assertEqual((r.name, r.detail), ("Brave", "browser"))

    def test_v8_heap_hint(self):
        r = detect("chrome.exe", [], ["chrome.exe", "--type=renderer", "--js-flags=--max-old-space-size=4096"])
        self.assertIn((HINT, "V8 heap limit 4.00G (--js-flags)"), r.evidence)

    def test_java_xmx(self):
        r = detect("java.exe", ["jvm.dll"], ["java", "-Xmx2g", "-jar", "/opt/app/server.jar"])
        self.assertEqual((r.name, r.detail), ("Java", "server.jar"))
        self.assertTrue(any(level == HINT and "2.00G" in text for level, text in r.evidence))

    def test_dotnet_core_vs_framework(self):
        self.assertEqual(detect("app.exe", ["coreclr.dll"]).name, ".NET")
        self.assertEqual(detect("app.exe", ["clr.dll"]).name, ".NET Framework")
        self.assertEqual(detect("app", ["libcoreclr.so"]).name, ".NET")

    def test_node_script_and_limit(self):
        r = detect("node.exe", [], ["node", "--max-old-space-size=8192", "server.js"])
        self.assertEqual((r.name, r.detail), ("Node.js", "server.js"))
        self.assertTrue(any("8.00G" in t for _, t in r.evidence))

    def test_python_version_from_dll(self):
        r = detect("python.exe", ["python314.dll", "torch_cpu.dll"], ["python", "-m", "http.server"])
        self.assertEqual(r.name, "Python 3.14")
        self.assertEqual(r.detail, "http.server")
        self.assertTrue(any("PyTorch" in t for _, t in r.evidence))

    def test_python_linux_lib(self):
        self.assertEqual(detect("python3", ["libpython3.12.so.1.0"]).name, "Python 3.12")

    def test_vm_host(self):
        r = detect("vmmemWSL", [])
        self.assertEqual(r.name, "VM")
        self.assertTrue(any(".wslconfig" in t for _, t in r.evidence))

    def test_compression_store(self):
        self.assertEqual(detect("MemCompression").detail, "compression store")
        self.assertEqual(detect("Memory Compression").detail, "compression store")

    def test_llm_server(self):
        r = detect("llama-server.exe", [], ["llama-server", "-m", r"D:\models\qwen.gguf", "--no-mmap"])
        self.assertEqual((r.name, r.detail), ("LLM", "llama.cpp"))
        texts = [t for _, t in r.evidence]
        self.assertIn("model qwen.gguf", texts)
        self.assertTrue(any("--no-mmap" in t for t in texts))

    def test_database(self):
        r = detect("redis-server", [], ["redis-server", "--maxmemory", "2gb"])
        self.assertEqual(r.detail, "Redis")
        self.assertIn((HINT, "maxmemory 2gb"), r.evidence)

    def test_firefox_content(self):
        r = detect("firefox.exe", ["xul.dll"], ["firefox.exe", "-contentproc", "12", "tab"])
        self.assertEqual((r.name, r.detail), ("Firefox", "tab"))

    def test_wsl_service_is_not_a_container(self):
        self.assertIsNone(detect("wsl-pro-service", [], ["/usr/libexec/wsl-pro-service"]))

    def test_unknown(self):
        self.assertIsNone(detect("notepad.exe", ["ntdll.dll", "user32.dll"], ["notepad.exe"]))


if __name__ == "__main__":
    unittest.main()
