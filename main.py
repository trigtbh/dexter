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
        # Forensics — mix of Rust + system tools
        "strings_extract": lambda i: run_script("strings_extract", i),
        "magic_bytes":     lambda i: run_script("magic_bytes", i),
        "lsb_extract":     lambda i: run_script("lsb_extract", i),
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