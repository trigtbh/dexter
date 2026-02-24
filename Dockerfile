FROM kalilinux/kali-rolling

# ── System deps ───────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    # Python + FastAPI runtime
    python3 python3-pip \
    # Rust toolchain (for compiling scripts/)
    rustc cargo \
    # Ruby (used to install zsteg via gem) and build tools
    ruby-full build-essential \
    # Forensics tools called by scripts
    steghide \
    exiftool \
    binwalk \
    foremost \
    && gem install zsteg --no-document \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install fastapi uvicorn --break-system-packages

# ── Copy sources ──────────────────────────────────────────────────────────────
WORKDIR /opt/dexter
COPY scripts/ ./scripts_src/
COPY main.py   ./main.py

# ── Compile every .rs file in scripts/ into a binary of the same name ─────────
RUN mkdir -p scripts && \
    for src in scripts_src/*.rs; do \
        name=$(basename "$src" .rs); \
        echo "Compiling $name..."; \
        rustc -O "$src" -o "scripts/$name"; \
    done

# ── Workspace volume (user drops challenge files here) ────────────────────────
RUN mkdir -p /workspace
VOLUME ["/workspace"]

EXPOSE 7777
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7777"]