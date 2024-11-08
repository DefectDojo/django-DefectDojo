FROM mcr.microsoft.com/devcontainers/base:ubuntu-22.04

RUN apt-get update && \
    apt-get install -y \
    ca-certificates \
    nodejs \
    npm \
    wget && \
    update-ca-certificates

ARG HUGO_VERSION="0.131.0"
RUN wget --quiet "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_Linux-64bit.tar.gz" && \
    tar xzf hugo_extended_${HUGO_VERSION}_Linux-64bit.tar.gz && \
    rm -r hugo_extended_${HUGO_VERSION}_Linux-64bit.tar.gz && \
    mv hugo /usr/bin && \
    chmod 755 /usr/bin/hugo

WORKDIR /src
COPY ./ /src
