#!/bin/sh
# sandfort host setup: sandbox egress and cloud-metadata blocking for Linux Docker hosts.
#
# Run as root on the Docker host after dockerd has started (it creates DOCKER-USER), and
# again after every reboot or iptables flush, e.g. from a systemd unit ordered
# After=docker.service. Re-running is safe: the script owns two chains, rebuilds them from
# scratch, and keeps exactly one jump to each. The test suite only runs it with --dry-run,
# against stub executables (tests/test_host_setup_r58.py).
#
#   sudo sh deploy/host-setup.sh            # apply
#   sudo sh deploy/host-setup.sh --dry-run  # print the iptables commands only (DRY_RUN=1 works too)
#
# Network. Sandboxes that may reach the outside share the bridge network "sf-net"
# (label sandfort.managed=true, icc disabled). The platform creates it lazily on the first
# networked sandbox; this script creates it first, with a fixed bridge interface name, so
# the rules below always match the interface the sandboxes use. An existing network is
# reused (it must carry the label) and its actual interface name is looked up.
#
# Rules. DOCKER-USER is evaluated by Docker before its own FORWARD rules. One jump sends
# traffic entering from the sandbox bridge into SANDFORT-EGRESS, which holds, in order:
#   1. ESTABLISHED,RELATED -> RETURN  replies to flows already admitted (including
#                                     host-initiated ones such as the preview proxy) go on
#                                     to Docker's normal handling.
#   2. 169.254.0.0/16      -> REJECT  link-local, including the cloud instance-metadata
#                                     service 169.254.169.254 (instance credentials, user-data).
#   3. 100.64.0.0/10       -> REJECT  carrier-grade NAT space (provider-internal networks).
#   4. 168.63.129.16/32    -> REJECT  Azure wire server.
#   5. 10.0.0.0/8          -> REJECT  RFC 1918 private ranges: the host's LAN, VPC peers,
#   6. 172.16.0.0/12       -> REJECT  other sandboxes and internal services. Docker's
#   7. 192.168.0.0/16      -> REJECT  default address pools live inside these ranges too.
#   8. everything else     -> RETURN  public internet: Docker's rules accept and masquerade.
# REJECT (not DROP) makes a blocked connection fail fast instead of hanging until timeout.
# IPv6: when ip6tables exists, the same chain name in ip6tables rejects fe80::/10 and fc00::/7
# (otherwise a warning is printed and IPv6 is left unfiltered).
#
# Host INPUT. Traffic from a sandbox to the host's own address on the bridge (the gateway)
# never crosses FORWARD, so DOCKER-USER cannot see it. SANDFORT-HOST-GUARD, jumped from
# INPUT for the bridge interface, admits replies to host-initiated flows and rejects new
# connections from sandboxes to host services. Docker's embedded DNS answers inside each
# container's own network namespace and is unaffected.
#
# Not covered: IPv6 INPUT (no host-guard chain exists in ip6tables, so a sandbox with IPv6
# enabled can reach host services over IPv6), the AWS IPv6 metadata address fd00:ec2::254
# is inside fc00::/7 and so is
# rejected, but public IPv6 destinations are not filtered, and Docker's nftables firewall
# backend (no DOCKER-USER chain) is not supported.
#
# Default bridge. Image builds run on Docker's default bridge (docker0, override with
# SF_DEFAULT_BRIDGE_IFACE), not on sf-net, so that interface is hooked into the same two jumps:
# build containers cannot reach link-local, private ranges or host ports either. Replies to
# flows the host started are still admitted by the ESTABLISHED,RELATED rule first. Set
# SF_DEFAULT_BRIDGE_IFACE to an empty value on hosts with the default bridge disabled; the
# docker0 rules are then skipped.
#
# Build DNS. Containers on the default bridge get the host's upstream resolvers in their
# resolver file, and those can sit at a private address (cluster DNS behind systemd-resolved),
# which the private-range rejects would block. The default bridge therefore jumps to its own
# chain, SANDFORT-EGRESS-BUILD, which is SANDFORT-EGRESS plus RETURN rules for udp and tcp
# port 53 to each upstream resolver, placed before the rejects. The resolvers come from
# "resolvectl status", else from the non-loopback nameserver lines of SF_RESOLV_CONF (default
# /etc/resolv.conf). SF_BUILD_DNS (space-separated IPv4 addresses) replaces discovery. The
# sandbox bridges never get this exception.
#
# Egress proxy network. Sandboxes created with an egress allowlist join a second bridge,
# "sf-egress-net" (SF_EGRESS_NETWORK, interface SF_EGRESS_BRIDGE_IFACE). Their chain,
# SANDFORT-EGRESS-PROXY, holds only: ESTABLISHED,RELATED -> RETURN, the proxy address
# tcp to the proxy endpoint -> RETURN, and everything else -> REJECT.
# The endpoint never defaults to loopback silently. SF_EGRESS_PROXY ("addr" or "addr:port",
# an IPv4 address) wins. When it is unset the address comes from SANDFORT_EGRESS_PROXY_ADDRESS
# in the environment file SF_ENV_FILE (default sandfort.env next to this script; grepped as
# strict KEY=VALUE, never sourced), else from the IPv4 gateway of the egress network. The port
# is SF_EGRESS_PROXY_PORT, else the one in the address, else 3128 for a derived address; an
# explicit SF_EGRESS_PROXY without any port dies. The source used is printed. A loopback
# result dies (sandboxes cannot reach loopback) unless SF_ALLOW_LOOPBACK_PROXY=1, for hosts
# without the proxy. The final summary names the endpoint and the gateway and warns when they
# differ in address. A --dry-run on a fresh host (no network yet, so no gateway) prints a
# placeholder endpoint (172.18.0.1:3128, see DRY_RUN_GATEWAY_PLACEHOLDER) with a note; the
# real run creates the network first and reads its actual gateway.
# The IPv6 chain rejects everything but replies. Traffic to the host's own address never crosses
# DOCKER-USER, so that bridge is also hooked into INPUT through SANDFORT-HOST-GUARD-PROXY:
# replies, then exactly one new-connection exception (tcp to the proxy endpoint), then REJECT.
# Without this hook a sandbox on the allowlist bridge reaches every host service through INPUT.
# The FORWARD chain admits the same tcp address and port.
# Every named interface must exist before rules are written (iptables accepts an unknown -i
# silently); the script dies otherwise. With --dry-run the check only warns. The check uses
# "ip link show".
#
# DNS sink. SANDFORT_EGRESS_DNS_SINK_ADDRESS (environment, else SF_ENV_FILE; an IPv4 address,
# optionally ":53") adds one exception to SANDFORT-HOST-GUARD-PROXY, before the REJECT: udp and
# tcp port 53 to that address. The rules come from deploy/egress-dns-sink.sh, which this script
# sources. Unset means nothing is added (the dry run says so).
#
# Production. The server cannot observe these rules from inside its process; prod start
# requires SANDFORT_EGRESS_ACKNOWLEDGED=true after you ran this script on the node.

set -eu

NETWORK="${SF_NETWORK:-sf-net}"
BRIDGE_IFACE="${SF_BRIDGE_IFACE:-sf-br0}"  # used only when this script creates the network
MANAGED_LABEL="sandfort.managed"
EGRESS_CHAIN="SANDFORT-EGRESS"
BUILD_CHAIN="SANDFORT-EGRESS-BUILD"  # default bridge only: EGRESS_CHAIN plus resolver RETURNs
RESOLV_CONF="${SF_RESOLV_CONF:-/etc/resolv.conf}"
BUILD_DNS=""  # upstream resolver addresses admitted on the default bridge (set in main)
HOST_CHAIN="SANDFORT-HOST-GUARD"
PROXY_CHAIN="SANDFORT-EGRESS-PROXY"
PROXY_HOST_CHAIN="SANDFORT-HOST-GUARD-PROXY"
EGRESS_NETWORK="${SF_EGRESS_NETWORK:-sf-egress-net}"
EGRESS_BRIDGE_IFACE="${SF_EGRESS_BRIDGE_IFACE:-sf-br1}"  # used only when created here
# Default bridge (build containers); set to an empty value to skip its rules.
DEFAULT_BRIDGE_IFACE="${SF_DEFAULT_BRIDGE_IFACE-docker0}"
EGRESS_PROXY=""  # the only destination the egress network reaches (resolved in main)
EGRESS_PROXY_PORT=""  # the one tcp port opened on INPUT and FORWARD (resolved in main)
PROXY_SOURCE=""  # where the proxy endpoint came from (named in the output)
EGRESS_NETWORK_ENSURED=0  # 1 once the egress network exists (or its creation was printed)
DEFAULT_PROXY_PORT="3128"  # used with a derived address when no port is given
# Dry run on a fresh host only: the egress network is printed, not created, so it has no
# gateway yet. Docker's default address pool gives docker0 172.17.0.0/16 and the next bridge
# 172.18.0.0/16 (gateway 172.18.0.1); the dry run shows that address, the real run reads it.
DRY_RUN_GATEWAY_PLACEHOLDER="172.18.0.1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Compose environment file next to compose.prod.yml (the one redeploy-beta.sh sources).
ENV_FILE="${SF_ENV_FILE:-$SCRIPT_DIR/sandfort.env}"
# Link-local (covers the metadata address 169.254.169.254), carrier-grade NAT, Azure wire server.
BLOCKED_SPECIAL_RANGES="169.254.0.0/16 100.64.0.0/10 168.63.129.16/32"
BLOCKED_RANGES_V6="fe80::/10 fc00::/7"  # IPv6 link-local and unique-local
PRIVATE_RANGES="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
DRY_RUN="${DRY_RUN:-0}"

say() {
    printf 'host-setup: %s\n' "$*"
}

fail() {
    printf 'host-setup: error: %s\n' "$*" >&2
    exit 1
}

run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '+ %s\n' "$*"
        return 0
    fi
    "$@"
}

# run_quiet CMD...: run, with docker's own stdout (a network id) discarded. A dry run prints the
# command itself, which a plain "run ... >/dev/null" would swallow.
run_quiet() {
    if [ "$DRY_RUN" = "1" ]; then
        run "$@"
        return 0
    fi
    "$@" >/dev/null
}

# The DNS sink exception (udp and tcp 53 to the sink address) lives in a sibling file. A copy
# of this script without it keeps working: the exception is skipped and the output says so.
if [ -r "$SCRIPT_DIR/egress-dns-sink.sh" ]; then
    # shellcheck disable=SC1091 # path is computed at run time
    . "$SCRIPT_DIR/egress-dns-sink.sh"
else
    DNS_SINK=""
    resolve_dns_sink() {
        say "egress-dns-sink.sh not found next to host-setup.sh: DNS sink exception skipped"
    }
    add_dns_sink_exception() {
        return 0
    }
fi

# require_interface IFACE: die unless the interface exists (dry run: warn only).
require_interface() {
    [ -n "$1" ] || fail "empty interface name"
    if ip link show dev "$1" >/dev/null 2>&1; then
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        say "warning: interface $1 does not exist yet (dry run)"
        return 0
    fi
    fail "interface $1 does not exist; rules on an unknown -i would silently match nothing"
}

require_prerequisites() {
    [ "$(uname -s)" = "Linux" ] || fail "Linux hosts only (Docker Desktop manages its own VM)"
    command -v docker >/dev/null 2>&1 || fail "docker CLI not found"
    command -v iptables >/dev/null 2>&1 || fail "iptables not found"
    command -v ip >/dev/null 2>&1 || fail "ip (iproute2) not found"
    if [ "$DRY_RUN" != "1" ] && [ "$(id -u)" -ne 0 ]; then
        fail "run as root (iptables changes need it)"
    fi
    iptables -n -L DOCKER-USER >/dev/null 2>&1 \
        || fail "chain DOCKER-USER missing: start dockerd (iptables backend) first"
}

# egress_gateway: the IPv4 gateway of the egress network (empty when it does not exist yet).
egress_gateway() {
    command -v docker >/dev/null 2>&1 || return 0
    gw_out="$(docker network inspect \
        -f '{{range .IPAM.Config}}{{println .Gateway}}{{end}}' "$EGRESS_NETWORK" 2>/dev/null \
        || true)"
    for gw in $gw_out; do
        if is_ipv4 "$gw"; then
            printf '%s\n' "$gw"
            return 0
        fi
    done
    return 0
}

# env_file_value KEY: the value of KEY in ENV_FILE. The file is only grepped for a strict
# KEY=VALUE line (the last one wins), never sourced.
env_file_value() {
    [ -r "$ENV_FILE" ] || return 0
    env_value="$(grep "^$1=" "$ENV_FILE" | tail -n 1 \
        | cut -d= -f2- | tr -d '\r' || true)"
    case "$env_value" in
        \"*\") env_value="${env_value#\"}"; env_value="${env_value%\"}" ;;
        \'*\') env_value="${env_value#\'}"; env_value="${env_value%\'}" ;;
    esac
    printf '%s\n' "$env_value"
}

# parse_endpoint RAW LABEL DEFAULT_PORT: set EGRESS_PROXY and EGRESS_PROXY_PORT from RAW
# ("addr" or "addr:port"). The port is SF_EGRESS_PROXY_PORT, else the one in RAW, else
# DEFAULT_PORT; when none of them is known the script dies.
parse_endpoint() {
    addr="$1"
    label="$2"
    default_port="$3"
    var_port="${SF_EGRESS_PROXY_PORT:-}"
    addr="${addr#*://}"
    addr="${addr%%/*}"
    addr_port=""
    case "$addr" in
        *:*:*) fail "$label must be an IPv4 address (optionally addr:port): $addr" ;;
        *:*)
            addr_port="${addr##*:}"
            addr="${addr%:*}"
            ;;
    esac
    [ -n "$addr" ] || fail "$label has an empty address"
    is_ipv4 "$addr" || fail "$label must be an IPv4 address: $addr"
    if [ -n "$addr_port" ] && [ -n "$var_port" ] && [ "$addr_port" != "$var_port" ]; then
        fail "$label port $addr_port differs from SF_EGRESS_PROXY_PORT $var_port"
    fi
    port="${var_port:-${addr_port:-$default_port}}"
    [ -n "$port" ] || fail "proxy port unknown: set SF_EGRESS_PROXY_PORT or use" \
        "SF_EGRESS_PROXY=addr:port (the INPUT guard opens exactly one port)"
    case "$port" in
        *[!0-9]*) fail "proxy port is not a number: $port" ;;
    esac
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        fail "proxy port out of range: $port"
    fi
    EGRESS_PROXY="$addr"
    EGRESS_PROXY_PORT="$port"
}

# dry_run_without_egress_network: true under --dry-run while the egress network does not exist
# (its creation was only printed, so there is no gateway to read yet).
dry_run_without_egress_network() {
    [ "$DRY_RUN" = "1" ] || return 1
    ! docker network inspect "$EGRESS_NETWORK" >/dev/null 2>&1
}

# use_gateway_placeholder: dry run on a fresh host. Use the placeholder gateway with the
# default port so the rest of the dry run can be reviewed; the real run reads the gateway.
use_gateway_placeholder() {
    say "dry run: the $EGRESS_NETWORK gateway would be read after the network is created"
    parse_endpoint "$DRY_RUN_GATEWAY_PLACEHOLDER" "placeholder gateway" "$DEFAULT_PROXY_PORT"
    say "dry run: using placeholder endpoint $EGRESS_PROXY:$EGRESS_PROXY_PORT (the default" \
        "subnet gateway of $EGRESS_NETWORK); the real run resolves the actual gateway, so" \
        "the address in the rules below may differ"
    PROXY_SOURCE="dry-run placeholder for the gateway of docker network $EGRESS_NETWORK"
}

# derive_proxy_endpoint: SF_EGRESS_PROXY is unset. Order: the env file variable, then the
# egress network gateway with the default port.
derive_proxy_endpoint() {
    if [ -n "${SF_ENV_FILE:-}" ] && [ ! -r "$ENV_FILE" ]; then
        fail "SF_ENV_FILE $ENV_FILE is not readable"
    fi
    from_file="$(env_file_value SANDFORT_EGRESS_PROXY_ADDRESS)"
    if [ -n "$from_file" ]; then
        parse_endpoint "$from_file" SANDFORT_EGRESS_PROXY_ADDRESS "$DEFAULT_PROXY_PORT"
        PROXY_SOURCE="SANDFORT_EGRESS_PROXY_ADDRESS in $ENV_FILE"
        return 0
    fi
    # A fresh host has no egress network yet, so it has no gateway either: create it first.
    ensure_egress_network
    gateway="$(egress_gateway)"
    if [ -z "$gateway" ] && dry_run_without_egress_network; then
        use_gateway_placeholder
        return 0
    fi
    [ -n "$gateway" ] || fail "cannot derive the egress proxy address: SF_EGRESS_PROXY is" \
        "unset, $ENV_FILE has no SANDFORT_EGRESS_PROXY_ADDRESS and network $EGRESS_NETWORK" \
        "has no gateway; set SF_EGRESS_PROXY=addr:port (the address sandboxes reach the proxy on)"
    parse_endpoint "$gateway" "gateway of $EGRESS_NETWORK" "$DEFAULT_PROXY_PORT"
    PROXY_SOURCE="gateway of docker network $EGRESS_NETWORK"
}

# resolve_proxy_endpoint: set EGRESS_PROXY (IPv4 address) and EGRESS_PROXY_PORT. Never falls
# back to loopback silently: a loopback result dies unless SF_ALLOW_LOOPBACK_PROXY=1.
resolve_proxy_endpoint() {
    if [ -n "${SF_EGRESS_PROXY:-}" ]; then
        parse_endpoint "$SF_EGRESS_PROXY" SF_EGRESS_PROXY ""
        PROXY_SOURCE="SF_EGRESS_PROXY"
    else
        derive_proxy_endpoint
    fi
    case "$EGRESS_PROXY" in
        127.*)
            [ "${SF_ALLOW_LOOPBACK_PROXY:-0}" = "1" ] || fail "egress proxy $EGRESS_PROXY is" \
                "loopback and sandboxes cannot reach loopback; set SF_EGRESS_PROXY to the" \
                "address they reach the proxy on (or SF_ALLOW_LOOPBACK_PROXY=1 on a host" \
                "without the proxy)"
            say "warning: loopback proxy allowed by SF_ALLOW_LOOPBACK_PROXY=1"
            ;;
    esac
    say "egress proxy endpoint $EGRESS_PROXY:$EGRESS_PROXY_PORT (source: $PROXY_SOURCE)"
}

# ensure_network NAME IFACE: create the managed bridge NAME unless it already exists.
ensure_network() {
    net="$1"
    bridge="$2"
    if docker network inspect "$net" >/dev/null 2>&1; then
        label="$(docker network inspect -f "{{index .Labels \"$MANAGED_LABEL\"}}" "$net")"
        [ "$label" = "true" ] \
            || fail "network $net exists but is not labelled $MANAGED_LABEL=true"
        return 0
    fi
    say "creating network $net on bridge interface $bridge"
    if [ "$net" = "$EGRESS_NETWORK" ]; then
        # The egress network stays IPv4-only: the host IPv6 INPUT chain has no guard for it, and
        # a daemon may default bridges to IPv6 unless told otherwise.
        run_quiet docker network create \
            --driver bridge \
            --ipv6=false \
            --opt com.docker.network.bridge.enable_icc=false \
            --opt "com.docker.network.bridge.name=$bridge" \
            --label "$MANAGED_LABEL=true" \
            "$net"
        return 0
    fi
    run_quiet docker network create \
        --driver bridge \
        --opt com.docker.network.bridge.enable_icc=false \
        --opt "com.docker.network.bridge.name=$bridge" \
        --label "$MANAGED_LABEL=true" \
        "$net"
}

# ensure_egress_network: ensure_network for the egress network, at most once per run (the
# gateway fallback of the endpoint resolution needs it before main's own ensure step).
ensure_egress_network() {
    [ "$EGRESS_NETWORK_ENSURED" = "1" ] && return 0
    ensure_network "$EGRESS_NETWORK" "$EGRESS_BRIDGE_IFACE"
    EGRESS_NETWORK_ENSURED=1
}

# bridge_interface NAME FALLBACK_IFACE: the bridge interface of network NAME.
bridge_interface() {
    net="$1"
    fallback="$2"
    if ! docker network inspect "$net" >/dev/null 2>&1; then
        printf '%s\n' "$fallback"  # dry run before the network exists
        return 0
    fi
    named="$(docker network inspect \
        -f '{{index .Options "com.docker.network.bridge.name"}}' "$net")"
    if [ -n "$named" ]; then
        printf '%s\n' "$named"
        return 0
    fi
    network_id="$(docker network inspect -f '{{.Id}}' "$net")"
    printf 'br-%s\n' "$(printf '%s' "$network_id" | cut -c1-12)"  # Docker's generated name
}

reset_chain() {
    chain="$1"
    if iptables -n -L "$chain" >/dev/null 2>&1; then
        run iptables -F "$chain"
    else
        run iptables -N "$chain"
    fi
}

# Delete every jump from chain $1 to chain $2 (a recreated network may have a new interface).
remove_jumps() {
    parent="$1"
    chain="$2"
    iptables -S "$parent" | grep -- "-j $chain\$" | sed 's/^-A /-D /' | while read -r rule; do
        # shellcheck disable=SC2086 # the saved rule is deliberately word-split into arguments
        run iptables $rule
    done
}

# is_ipv4 ADDR: true for a dotted quad of digits (no range check).
is_ipv4() {
    case "$1" in
        "" | *[!0-9.]* | .* | *. | *..*) return 1 ;;
    esac
    dots="$(printf '%s' "$1" | tr -cd . | wc -c)"
    [ $dots -eq 3 ]
}

# add_build_dns ADDR: append ADDR to BUILD_DNS once.
add_build_dns() {
    case " $BUILD_DNS " in
        *" $1 "*) return 0 ;;
    esac
    BUILD_DNS="${BUILD_DNS:+$BUILD_DNS }$1"
}

# discover_build_dns: set BUILD_DNS to the upstream resolvers of the default bridge.
discover_build_dns() {
    BUILD_DNS=""
    if [ -n "${SF_BUILD_DNS:-}" ]; then
        for addr in $SF_BUILD_DNS; do
            is_ipv4 "$addr" || fail "SF_BUILD_DNS entry is not an IPv4 address: $addr"
            add_build_dns "$addr"
        done
        return 0
    fi
    found=""
    if command -v resolvectl >/dev/null 2>&1; then
        found="$(resolvectl status 2>/dev/null | grep 'DNS Server' | grep -v Fallback \
            | sed 's/^[^:]*://' || true)"
    fi
    if [ -z "$found" ] && [ -r "$RESOLV_CONF" ]; then
        found="$(awk '$1 == "nameserver" { print $2 }' "$RESOLV_CONF" || true)"
    fi
    for addr in $found; do
        is_ipv4 "$addr" || continue
        case "$addr" in
            127.*) continue ;;
        esac
        add_build_dns "$addr"
    done
}

# build_egress_chain CHAIN [RESOLVER...]: the egress chain; each RESOLVER gets udp and tcp
# port 53 RETURN rules ahead of the rejects.
build_egress_chain() {
    chain="$1"
    shift
    reset_chain "$chain"
    run iptables -A "$chain" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for resolver in "$@"; do
        for proto in udp tcp; do
            run iptables -A "$chain" -p "$proto" -d "$resolver" --dport 53 -j RETURN
        done
    done
    for range in $BLOCKED_SPECIAL_RANGES $PRIVATE_RANGES; do
        run iptables -A "$chain" -d "$range" -j REJECT --reject-with icmp-admin-prohibited
    done
    run iptables -A "$chain" -j RETURN
}

# IPv6 mirror of the egress chain. Without ip6tables the step warns and does nothing.
build_egress_chain_v6() {
    if ! command -v ip6tables >/dev/null 2>&1; then
        say "warning: ip6tables not found; IPv6 egress is not filtered (sf-net is IPv4-only" \
            "unless IPv6 was enabled on it)"
        return 0
    fi
    if ip6tables -n -L "$EGRESS_CHAIN" >/dev/null 2>&1; then
        run ip6tables -F "$EGRESS_CHAIN"
    else
        run ip6tables -N "$EGRESS_CHAIN"
    fi
    run ip6tables -A "$EGRESS_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    for range in $BLOCKED_RANGES_V6; do
        run ip6tables -A "$EGRESS_CHAIN" -d "$range" -j REJECT --reject-with icmp6-adm-prohibited
    done
    run ip6tables -A "$EGRESS_CHAIN" -j RETURN
}

install_jumps_v6() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    if ip6tables -n -L DOCKER-USER >/dev/null 2>&1; then
        ip6tables -S DOCKER-USER | grep -- "-j $EGRESS_CHAIN\$" | sed 's/^-A /-D /' \
            | while read -r rule; do
                # shellcheck disable=SC2086 # the saved rule is deliberately word-split
                run ip6tables $rule
            done
        for jump_iface in "$@"; do
            run ip6tables -I DOCKER-USER 1 -i "$jump_iface" -j "$EGRESS_CHAIN"
        done
    else
        say "warning: ip6tables chain DOCKER-USER missing; IPv6 jump not installed"
    fi
}

build_host_chain() {
    reset_chain "$HOST_CHAIN"
    run iptables -A "$HOST_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    run iptables -A "$HOST_CHAIN" -j REJECT --reject-with icmp-admin-prohibited
}

# The egress-proxy network may reach the proxy address and receive replies, nothing else.
build_proxy_chain() {
    reset_chain "$PROXY_CHAIN"
    run iptables -A "$PROXY_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    run iptables -A "$PROXY_CHAIN" -p tcp -d "$EGRESS_PROXY" --dport "$EGRESS_PROXY_PORT" \
        -j RETURN
    run iptables -A "$PROXY_CHAIN" -j REJECT --reject-with icmp-admin-prohibited
}

# INPUT guard for the egress-proxy bridge: replies and the proxy address and port only.
build_proxy_host_chain() {
    reset_chain "$PROXY_HOST_CHAIN"
    run iptables -A "$PROXY_HOST_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    run iptables -A "$PROXY_HOST_CHAIN" -p tcp -d "$EGRESS_PROXY" --dport "$EGRESS_PROXY_PORT" \
        -j RETURN
    add_dns_sink_exception "$PROXY_HOST_CHAIN"
    run iptables -A "$PROXY_HOST_CHAIN" -j REJECT --reject-with icmp-admin-prohibited
}

build_proxy_chain_v6() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    if ip6tables -n -L "$PROXY_CHAIN" >/dev/null 2>&1; then
        run ip6tables -F "$PROXY_CHAIN"
    else
        run ip6tables -N "$PROXY_CHAIN"
    fi
    run ip6tables -A "$PROXY_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    run ip6tables -A "$PROXY_CHAIN" -j REJECT --reject-with icmp6-adm-prohibited
}

install_proxy_jump() {
    iface="$1"
    remove_jumps DOCKER-USER "$PROXY_CHAIN"
    remove_jumps INPUT "$PROXY_HOST_CHAIN"
    run iptables -I DOCKER-USER 1 -i "$iface" -j "$PROXY_CHAIN"
    run iptables -I INPUT 1 -i "$iface" -j "$PROXY_HOST_CHAIN"
    if command -v ip6tables >/dev/null 2>&1 && ip6tables -n -L DOCKER-USER >/dev/null 2>&1; then
        run ip6tables -I DOCKER-USER 1 -i "$iface" -j "$PROXY_CHAIN"
    fi
}

# install_jumps IFACE [DEFAULT_IFACE]: hook the sandbox bridge into the egress chain and the
# default bridge (when given) into the build chain; both go through the host-guard on INPUT.
# Existing jumps are removed first, so a re-run leaves exactly one jump per interface.
install_jumps() {
    remove_jumps DOCKER-USER "$EGRESS_CHAIN"
    remove_jumps DOCKER-USER "$BUILD_CHAIN"
    remove_jumps INPUT "$HOST_CHAIN"
    run iptables -I DOCKER-USER 1 -i "$1" -j "$EGRESS_CHAIN"
    run iptables -I INPUT 1 -i "$1" -j "$HOST_CHAIN"
    if [ -n "${2:-}" ]; then
        run iptables -I DOCKER-USER 1 -i "$2" -j "$BUILD_CHAIN"
        run iptables -I INPUT 1 -i "$2" -j "$HOST_CHAIN"
    fi
}

# report_proxy_vs_gateway: name the proxy endpoint and the egress network gateway; warn when
# the rules were built for a different address than the one sandboxes see as the host.
report_proxy_vs_gateway() {
    final_gw="$(egress_gateway)"
    say "proxy endpoint $EGRESS_PROXY:$EGRESS_PROXY_PORT; $EGRESS_NETWORK gateway" \
        "${final_gw:-unknown (network not created yet)}"
    if [ -n "$final_gw" ] && [ "$final_gw" != "$EGRESS_PROXY" ]; then
        say "WARNING: the rules admit $EGRESS_PROXY but the $EGRESS_NETWORK gateway is" \
            "$final_gw; if the proxy listens on the host, sandboxes reach it at $final_gw and" \
            "get No route to host. Rerun with SF_EGRESS_PROXY=$final_gw:$EGRESS_PROXY_PORT" \
            "unless the proxy really is on $EGRESS_PROXY"
    fi
}

main() {
    for arg in "$@"; do
        case "$arg" in
            --dry-run) DRY_RUN=1 ;;
            *) fail "unknown argument: $arg (only --dry-run is accepted)" ;;
        esac
    done
    require_prerequisites
    resolve_proxy_endpoint
    resolve_dns_sink
    ensure_network "$NETWORK" "$BRIDGE_IFACE"
    ensure_egress_network
    iface="$(bridge_interface "$NETWORK" "$BRIDGE_IFACE")"
    egress_iface="$(bridge_interface "$EGRESS_NETWORK" "$EGRESS_BRIDGE_IFACE")"
    require_interface "$iface"
    require_interface "$egress_iface"
    if [ -n "$DEFAULT_BRIDGE_IFACE" ]; then
        require_interface "$DEFAULT_BRIDGE_IFACE"
        say "default bridge interface (build containers): $DEFAULT_BRIDGE_IFACE"
        default_ifaces="$DEFAULT_BRIDGE_IFACE"
        discover_build_dns
        say "build DNS resolvers (default bridge only): ${BUILD_DNS:-none discovered}"
    else
        say "SF_DEFAULT_BRIDGE_IFACE is empty: skipping the docker0 (default bridge) rules"
        default_ifaces=""
    fi
    say "sandbox bridge interface: $iface"
    say "egress proxy bridge interface: $egress_iface (proxy $EGRESS_PROXY)"
    build_egress_chain "$EGRESS_CHAIN"
    if [ -n "$default_ifaces" ]; then
        # shellcheck disable=SC2086 # BUILD_DNS is a space-separated address list
        build_egress_chain "$BUILD_CHAIN" $BUILD_DNS
    fi
    build_egress_chain_v6
    build_host_chain
    install_jumps "$iface" "$default_ifaces"
    # shellcheck disable=SC2086
    install_jumps_v6 "$iface" $default_ifaces
    build_proxy_chain
    build_proxy_host_chain
    build_proxy_chain_v6
    install_proxy_jump "$egress_iface"
    say "done (IPv4 iptables): $NETWORK sandboxes are blocked from private ranges and host" \
        "services; $EGRESS_NETWORK sandboxes are limited to tcp" \
        "$EGRESS_PROXY:$EGRESS_PROXY_PORT on INPUT and FORWARD"
    report_proxy_vs_gateway
    if [ -n "$DNS_SINK" ]; then
        say "DNS sink exception: udp and tcp 53 to $DNS_SINK on $PROXY_HOST_CHAIN"
    fi
    if [ -n "$default_ifaces" ]; then
        say "default bridge $default_ifaces: port 53 allowed to ${BUILD_DNS:-no resolvers}"
    fi
    say "not closed: IPv6 INPUT has no host guard, and the Docker nftables backend is" \
        "unsupported; do not treat allowlist sandboxes as reaching only the proxy yet"
}

main "$@"
