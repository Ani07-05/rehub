# syntax=docker/dockerfile:1
ARG ZEEK_IMAGE=zeek/zeek:8.0.10@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3

FROM ${ZEEK_IMAGE} AS plugins
ARG ICSNPP_S7COMM_SHA=7ebeb03a0f954541369361651d1c27d09a64b5a3
ARG ICSNPP_ENIP_SHA=808f90b0d834481a1368dbcad650f63c88550991
ARG ICSNPP_MODBUS_SHA=27f22b41fd9839c0bad1b98df9c6289e578fd02a
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake git ca-certificates flex bison libpcap-dev libssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN set -e; \
    for spec in s7comm:${ICSNPP_S7COMM_SHA} enip:${ICSNPP_ENIP_SHA} modbus:${ICSNPP_MODBUS_SHA}; do \
        name=${spec%%:*}; sha=${spec##*:}; \
        git clone https://github.com/cisagov/icsnpp-$name /src/icsnpp-$name; \
        git -C /src/icsnpp-$name checkout $sha; \
        zkg install /src/icsnpp-$name --force --nodeps; \
    done

FROM ${ZEEK_IMAGE} AS suricata
ARG SURICATA_VERSION=8.0.7
ARG SURICATA_SHA256=a9d46a9c8f40e81f8a6df3ecc2c5a9a8e8da985876299108d92da547c013ba8c
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential autoconf automake libtool pkg-config cargo rustc curl ca-certificates \
       libpcre2-dev libyaml-dev libjansson-dev libmagic-dev libpcap-dev zlib1g-dev libcap-ng-dev liblz4-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/suricata.tar.gz https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz \
    && echo "${SURICATA_SHA256}  /tmp/suricata.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/suricata.tar.gz -C /tmp \
    && cd /tmp/suricata-${SURICATA_VERSION} \
    && ./configure --prefix=/opt/suricata --sysconfdir=/opt/suricata/etc --localstatedir=/var --disable-gccmarch-native \
    && make -j"$(nproc)" \
    && make install install-conf \
    && chmod -R a+rX /opt/suricata

FROM ${ZEEK_IMAGE}
COPY --from=plugins /usr/local/zeek /usr/local/zeek
COPY --from=suricata /opt/suricata /opt/suricata
COPY --from=ghcr.io/astral-sh/uv:0.12.21 /uv /usr/local/bin/uv
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark=4.4.18-0+deb13u1 \
       libpcre2-8-0 libyaml-0-2 libjansson4 libmagic1t64 libpcap0.8t64 libcap-ng0 zlib1g liblz4-1 \
    && rm -rf /var/lib/apt/lists/*
COPY docker/zeek/rehub.zeek /opt/rehub/zeek/rehub.zeek
ARG RULES_FILE=docker/suricata/rehub.rules
COPY ${RULES_FILE} /opt/rehub/suricata/rehub.rules
WORKDIR /opt/rehub
COPY pyproject.toml uv.lock ./
COPY src ./src
COPY fixtures ./fixtures
RUN UV_PYTHON=/usr/bin/python3 UV_PROJECT_ENVIRONMENT=/opt/rehub/venv uv sync --frozen --no-dev
ENV PATH=/opt/rehub/venv/bin:/usr/local/zeek/bin:/opt/suricata/bin:$PATH \
    REHUB_IN_IMAGE=1
CMD ["rehub", "--help"]
