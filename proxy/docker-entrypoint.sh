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

export OS_BACKEND_URL OS_SERVER_NAME

mkdir -p /etc/nginx/conf.d

for template in /etc/openresty/templates/*.conf.template; do
    [ -e "$template" ] || continue
    output="/etc/nginx/conf.d/$(basename "$template" .template)"
    envsubst '${OS_BACKEND_URL} ${OS_SERVER_NAME}' < "$template" > "$output"
    echo "openshield: rendered $output (backend: $OS_BACKEND_URL)"
done

# Fail fast on a bad configuration rather than starting and serving errors.
/usr/local/openresty/bin/openresty -t

exec "$@"
