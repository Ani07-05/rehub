# syntax=docker/dockerfile:1
ARG ZEEK_IMAGE=zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3

FROM ${ZEEK_IMAGE} AS plugins
ARG ICSNPP_S7COMM_SHA=7ebeb03a0f954541369361651d1c27d09a64b5a3
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates flex bison libpcap-dev libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/cisagov/icsnpp-s7comm /src/icsnpp-s7comm \
    && git -C /src/icsnpp-s7comm checkout ${ICSNPP_S7COMM_SHA} \
    && zkg install /src/icsnpp-s7comm --force --nodeps

FROM ${ZEEK_IMAGE}
COPY --from=plugins /usr/local/zeek /usr/local/zeek
COPY --from=ghcr.io/astral-sh/uv:0.12.21 /uv /usr/local/bin/uv
COPY docker/zeek/rehub.zeek /opt/rehub/zeek/rehub.zeek
WORKDIR /opt/rehub
COPY pyproject.toml uv.lock ./
COPY src ./src
COPY fixtures ./fixtures
RUN UV_PYTHON=/usr/bin/python3 UV_PROJECT_ENVIRONMENT=/opt/rehub/venv uv sync --frozen --no-dev
ENV PATH=/opt/rehub/venv/bin:/usr/local/zeek/bin:$PATH \
    REHUB_IN_IMAGE=1
CMD ["rehub", "--help"]
