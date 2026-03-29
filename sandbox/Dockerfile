FROM python:3.11-slim

# System tools
RUN apt-get update && apt-get install -y \
    binutils \
    libimage-exiftool-perl \
    binwalk \
    yara \
    libssl-dev \
    strace \
    curl \
    mono-utils \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    jsbeautifier \
    pefile \
    yara-python \
    python-dotenv \
    dnfile

WORKDIR /analysis
COPY analyze.py .
COPY dynamic_analyze.js .
COPY rules/ ./rules/

USER nobody

ENTRYPOINT ["python3", "analyze.py"]
