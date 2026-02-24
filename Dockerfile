FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    hashcat john \
    steghide exiftool \
    binwalk foremost \
    netcat-openbsd curl wget \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/ /opt/dexter/scripts/

# Expose a socket or port the TUI talks to
EXPOSE 7777

CMD ["python3", "/opt/dexter/scripts/main.py"]