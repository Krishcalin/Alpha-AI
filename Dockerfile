FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Core security tooling — extend as more wrappers are added
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        nmap \
        nuclei \
        gobuster \
        ffuf \
        sqlmap \
        nikto \
        enum4linux \
        crackmapexec \
        hydra \
        exploitdb \
        dnsutils \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/alpha-ai

COPY pyproject.toml README.md LICENSE ./
COPY alpha_ai ./alpha_ai

RUN pip3 install --break-system-packages --no-cache-dir .

EXPOSE 8000
CMD ["alpha-api", "--host", "0.0.0.0", "--port", "8000"]
