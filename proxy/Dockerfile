# open-shield proxy — OpenResty with the access-phase hook.
#
# Nginx and its Lua bindings are third-party infrastructure (§3.1). What is ours
# is one script: collect the request, ask the engine, act on the answer.
# lua-resty-http gives the access phase a connection pool to the engine, which
# is what keeps the added latency inside the budget of §8.2.
#
# It is fetched from its tagged release rather than through luarocks: the
# luarocks client shipped in the OpenResty images cannot load the registry
# manifest under LuaJIT.
FROM alpine:3.21 AS luadeps

ARG RESTY_HTTP_VERSION=0.17.2

RUN apk add --no-cache curl tar \
    && curl -fsSL -o /tmp/resty-http.tar.gz \
        "https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v${RESTY_HTTP_VERSION}.tar.gz" \
    && mkdir -p /lualib \
    && tar -xzf /tmp/resty-http.tar.gz -C /tmp \
    && cp -r "/tmp/lua-resty-http-${RESTY_HTTP_VERSION}/lib/resty" /lualib/

FROM openresty/openresty:1.27.1.1-0-alpine

# gettext supplies envsubst for the entrypoint; curl backs the healthcheck.
RUN apk add --no-cache gettext curl

COPY --from=luadeps /lualib/resty/ /usr/local/openresty/site/lualib/resty/

# The image ships a demo site at /etc/nginx/conf.d/default.conf with
# `server_name localhost`. An exact server_name match beats a default_server,
# so leaving it in place means every request whose Host is "localhost" — which
# is every request during testing — is served OpenResty's welcome page instead
# of being proxied and filtered.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/       /etc/openresty/lua/
COPY conf.d/    /etc/openresty/templates/

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 80 443

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${OS_LISTEN_PORT:-${PORT:-80}}/__openshield/health" || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
