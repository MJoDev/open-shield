#!/bin/sh
# Renders the server configuration from the environment, then starts OpenResty.
#
# Nginx cannot read environment variables inside directives such as proxy_pass,
# so the few settings that vary per deployment are substituted here. Only the
# named variables are expanded: a blanket envsubst would eat every $variable
# nginx uses at request time ($remote_addr, $request_uri, and the rest).
set -eu

: "${OS_BACKEND_URL:?OS_BACKEND_URL is required (the address of the site to protect, e.g. http://app:3000)}"
: "${OS_SERVER_NAME:=_}"

# The listening port is fixed at 80 under Compose, where the host mapping
# decides what the outside sees. A platform that assigns the port instead
# (Railway, Fly, Cloud Run) injects PORT, and the server has to follow it or
# the health check never passes.
OS_LISTEN_PORT="${OS_LISTEN_PORT:-${PORT:-80}}"

# Nginx resolves proxy_pass and the Lua cosocket at request time, and it does
# not read /etc/resolv.conf to do it — the resolver has to be named in the
# configuration. Reading the nameserver from resolv.conf yields 127.0.0.11
# under Compose, where Docker's embedded DNS is what makes a restarted backend
# reachable at its new address, and the platform's own resolver anywhere else.
if [ -z "${OS_RESOLVER:-}" ]; then
    OS_RESOLVER="$(awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf)"
    # An IPv6 nameserver has to be bracketed in the resolver directive.
    case "$OS_RESOLVER" in
        *:*) OS_RESOLVER="[$OS_RESOLVER]" ;;
    esac
fi
: "${OS_RESOLVER:?no nameserver found in /etc/resolv.conf; set OS_RESOLVER explicitly}"

# Docker's embedded DNS answers AAAA queries in a way that makes nginx report
# the host as not found, so IPv6 stays off by default. It has to be turned on
# where the origin publishes AAAA records only — a Railway private domain does.
: "${OS_RESOLVER_IPV6:=off}"

export OS_BACKEND_URL OS_SERVER_NAME OS_LISTEN_PORT OS_RESOLVER OS_RESOLVER_IPV6

# real_ip, rendered only when a trusted proxy is declared.
#
# Behind an edge that terminates TLS, remote_addr is the edge's address, and
# ipblock and ratelimit would then key every request on Earth to a single IP —
# silently useless rather than visibly broken. Trusting the header is only safe
# when something in front is known to overwrite it, which is why this is opt-in
# rather than a default. See OS_TRUSTED_PROXY in deploy/.env.example.
mkdir -p /etc/nginx/realip
rm -f /etc/nginx/realip/*.conf
if [ -n "${OS_TRUSTED_PROXY:-}" ]; then
    : "${OS_REAL_IP_HEADER:=X-Forwarded-For}"
    realip="/etc/nginx/realip/10-realip.conf"
    : > "$realip"
    for cidr in $OS_TRUSTED_PROXY; do
        echo "set_real_ip_from $cidr;" >> "$realip"
    done
    echo "real_ip_header $OS_REAL_IP_HEADER;" >> "$realip"
    echo "real_ip_recursive on;"              >> "$realip"
    echo "openshield: real_ip enabled from [$OS_TRUSTED_PROXY] via $OS_REAL_IP_HEADER"
fi

mkdir -p /etc/nginx/conf.d

for template in /etc/openresty/templates/*.conf.template; do
    [ -e "$template" ] || continue
    output="/etc/nginx/conf.d/$(basename "$template" .template)"
    envsubst '${OS_BACKEND_URL} ${OS_SERVER_NAME} ${OS_LISTEN_PORT} ${OS_RESOLVER} ${OS_RESOLVER_IPV6}' \
        < "$template" > "$output"
    echo "openshield: rendered $output (backend: $OS_BACKEND_URL, port: $OS_LISTEN_PORT, resolver: $OS_RESOLVER)"
done

# Fail fast on a bad configuration rather than starting and serving errors.
/usr/local/openresty/bin/openresty -t

exec "$@"
