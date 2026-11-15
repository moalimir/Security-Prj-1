FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PATH="/opt/venv/bin:$PATH"
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ make cmake clang llvm git python3 python3-venv binutils file ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv
WORKDIR /workspace
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN groupadd --gid 10001 validator && useradd --uid 10001 --gid validator --create-home validator
COPY --chown=validator:validator src/ ./src/
COPY --chown=validator:validator configs/ ./configs/
COPY --chown=validator:validator tests/ ./tests/
COPY --chown=validator:validator tools/ ./tools/
COPY --chown=validator:validator examples/ ./examples/
COPY --chown=validator:validator ci/ ./ci/
RUN mkdir -p /workspace/reports && chown validator:validator /workspace /workspace/reports
USER validator
RUN python tools/prepare_demo.py --output-dir /workspace/.demo
RUN python tools/prepare_targets.py
ENTRYPOINT ["python", "-m", "src"]
CMD ["--help"]
