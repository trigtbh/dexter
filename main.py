import subprocess
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()
SCRIPTS = Path("/opt/dexter/scripts")


class RunRequest(BaseModel):
    tool: str
    input: str


class RunResponse(BaseModel):
    success: bool
    output: str


def ok(output: str) -> RunResponse:
    return RunResponse(success=True, output=output.strip())


def err(msg: str) -> RunResponse:
    return RunResponse(success=False, output=msg)


def run_script(name: str, inp: str, timeout: int = 30) -> RunResponse:
    """
    Run a script from /opt/dexter/scripts/ with input piped to stdin.
    Scripts must read from stdin and write result to stdout.
    """
    script = SCRIPTS / name
    if not script.exists():
        return err(f"Script not found: {name}\nExpected at {script}")
    try:
        result = subprocess.run(
            [str(script)],
            input=inp,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0 and result.stderr:
            return err(result.stderr.strip())
        output = result.stdout
        if not output and result.stderr:
            # Some tools write to stderr (e.g. zsteg summary lines)
            output = result.stderr
        return ok(output)
    except subprocess.TimeoutExpired:
        return err(f"Script timed out after {timeout}s")
    except Exception as e:
        return err(f"Failed to run {name}: {e}")


def run_steghide(inp: str) -> RunResponse:
    """
    Expected format: <hex_bytes>::<pass>
    """
    import os, tempfile, binascii
    parts = inp.split("::", 1)
    if len(parts) < 2:
        return err("Format: hex bytes :: password")
    
    hex_bytes = parts[0].strip()
    password = parts[1].strip()

    try:
        data = binascii.unhexlify(hex_bytes)
    except Exception as e:
        return err(f"Invalid hex bytes: {e}")

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        file_path = f.name

    try:
        # Steghide extract
        res = subprocess.run(
            ["steghide", "extract", "-sf", file_path, "-p", password, "-xf", "/tmp/extracted"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if res.returncode != 0:
            return err(res.stderr or res.stdout or "Steghide failed")
        
        if os.path.exists("/tmp/extracted"):
                with open("/tmp/extracted", "r") as f:
                    out = f.read()
                os.remove("/tmp/extracted")
                return ok(f"Extracted content:\n{out}")
        return ok("Steghide ran successfully but found nothing?")
    except Exception as e:
        return err(f"Steghide error: {e}")
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


def run_system_tool(name: str, inp: str, args: list = None, timeout: int = 30) -> RunResponse:
    """
    Run a system tool on hex bytes input (saves to temp file).
    """
    import os, tempfile, binascii
    if args is None:
        args = []
    
    try:
        data = binascii.unhexlify(inp.strip())
    except Exception as e:
        return err(f"Invalid hex bytes: {e}")

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        file_path = f.name

    try:
        # Construct cmd: name + args + file_path
        cmd = [name] + args + [file_path]
        
        # Some tools output to stdout, some to stderr. Capture both.
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + "\n" + result.stderr
        return ok(output)
    except subprocess.TimeoutExpired:
        return err(f"Tool {name} timed out")
    except Exception as e:
        return err(f"Failed to run {name}: {e}")
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


# ─── Health ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


# ─── Router ───────────────────────────────────────────────────────────────────

@app.post("/run", response_model=RunResponse)
def run_tool(req: RunRequest) -> RunResponse:
    tool = req.tool.strip()
    inp = req.input.strip()

    routes = {
        # Encoding — all Rust scripts
        "base64_decode":   lambda i: run_script("base64_decode", i),
        "base64_encode":   lambda i: run_script("base64_encode", i),
        "hex_decode":      lambda i: run_script("hex_decode", i),
        "hex_encode":      lambda i: run_script("hex_encode", i),
        "binary_decode":   lambda i: run_script("binary_decode", i),
        "url_decode":      lambda i: run_script("url_decode", i),
        # Crypto — Rust scripts
        "rot13":           lambda i: run_script("rot13", i),
        "caesar_brute":    lambda i: run_script("caesar_brute", i),
        "xor_brute":       lambda i: run_script("xor_brute", i),
        "xor_key":         lambda i: run_script("xor_key", i),
        "rsa_decrypt":     lambda i: run_script("rsa_decrypt.py", i),
        # Forensics — mix of Rust + system tools
        "strings_extract": lambda i: run_script("strings_extract", i),
        "magic_bytes":     lambda i: run_script("magic_bytes", i),
        "lsb_extract":     lambda i: run_system_tool("zsteg", i, args=["-a"]),
        # For system tools, we save hex bytes to a temp file first
        "steghide":        run_steghide,
        "zsteg":           lambda i: run_system_tool("zsteg", i),
        "exiftool":        lambda i: run_system_tool("exiftool", i),
        "binwalk":         lambda i: run_system_tool("binwalk", i),
        "foremost":        lambda i: run_system_tool("foremost", i),
        # Hashing — Rust scripts
        "hash_identify":   lambda i: run_script("hash_identify", i),
        "md5":             lambda i: run_script("md5_hash", i),
        "sha256":          lambda i: run_script("sha256_hash", i),
    }

    handler = routes.get(tool)
    if handler is None:
        return err(f"Unknown tool: '{tool}'")

    try:
        return handler(inp)
    except Exception as e:
        return err(f"Unexpected error: {e}")