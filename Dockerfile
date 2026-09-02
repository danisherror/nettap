FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        tcpdump \
        tshark \
        iproute2 \
        util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY nettap ./nettap
RUN pip install --no-cache-dir -e .

VOLUME ["/data"]
ENTRYPOINT ["nettap", "--data-dir", "/data"]
CMD ["watch", "--all"]
