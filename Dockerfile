FROM python:3.11-slim

# links the image on ghcr.io to the repository (release.yml adds the rest)
LABEL org.opencontainers.image.source="https://github.com/danisherror/nettap" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump \
        tshark \
        iproute2 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml requirements.txt README.md LICENSE ./
RUN pip install --no-cache-dir -r requirements.txt
COPY nettap ./nettap
RUN pip install --no-cache-dir .

VOLUME ["/data"]
ENTRYPOINT ["nettap", "--data-dir", "/data"]
CMD ["watch", "--all"]
