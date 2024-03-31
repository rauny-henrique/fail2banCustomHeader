FROM alpine:3 AS build

# Fail2ban
ARG PLUGIN_MODULE_FAIL2BAN=github.com/rauny-henrique/fail2banCustomHeader
ARG PLUGIN_GIT_REPO_FAIL2BAN=https://github.com/rauny-henrique/fail2banCustomHeader.git
ARG PLUGIN_GIT_BRANCH_FAIL2BAN=main
RUN apk add --update git && \
    git clone ${PLUGIN_GIT_REPO_FAIL2BAN} /plugins-local/src/${PLUGIN_MODULE_FAIL2BAN} \
      --depth 1 --single-branch --branch ${PLUGIN_GIT_BRANCH_FAIL2BAN}

# Real-ip
ARG PLUGIN_MODULE_REALIP=github.com/rauny-henrique/traefik-get-real-ip
ARG PLUGIN_GIT_REPO_REALIP=https://github.com/rauny-henrique/traefik-get-real-ip.git
ARG PLUGIN_GIT_BRANCH_REALIP=master
RUN apk add --update git && \
    git clone ${PLUGIN_GIT_REPO_REALIP} /plugins-local/src/${PLUGIN_MODULE_REALIP} \
      --depth 1 --single-branch --branch ${PLUGIN_GIT_BRANCH_REALIP}

FROM traefik:v2.11

ARG VERSION=v2.11

RUN set -ex; \
	apkArch="$(apk --print-arch)"; \
	case "$apkArch" in \
		armhf) arch='armv6' ;; \
		aarch64) arch='arm64' ;; \
		x86_64) arch='amd64' ;; \
		s390x) arch='s390x' ;; \
		ppc64le) arch='ppc64le' ;; \
		*) echo >&2 "error: unsupported architecture: $apkArch"; exit 1 ;; \
	esac; \
	wget --quiet -O /tmp/traefik.tar.gz "https://github.com/rauny-henrique/traefik/raw/${VERSION}/dist/linux/$arch/traefik.tar.gz"; \
	tar xzvf /tmp/traefik.tar.gz -C /usr/local/bin traefik; \
	rm -f /tmp/traefik.tar.gz; \
	chmod +x /usr/local/bin/traefik

COPY --from=build /plugins-local /plugins-local

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
CMD ["traefik"]
