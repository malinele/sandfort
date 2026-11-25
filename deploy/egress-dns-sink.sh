# sandfort egress DNS sink: the host firewall part. Sourced by host-setup.sh, never run alone.
#
# On the "container" tier (runc) Docker's embedded resolver forwards external names to the
# servers named by the container's dns option. The proxy process serves a DNS sink on
# SANDFORT_EGRESS_DNS_SINK_ADDRESS (udp and tcp port 53, REFUSED for every query) and
# build_host_config points runc containers on the egress network at it (see
# docs/egress-v2-design.md section 6.2). This file adds the one firewall exception that lets
# those queries reach the sink: udp and tcp port 53 to the sink address, inside
# SANDFORT-HOST-GUARD-PROXY, before its final REJECT. Nothing else is opened: no forwarding
# rule, no ip6tables rule, no exception on any other chain.
#
# The address comes from SANDFORT_EGRESS_DNS_SINK_ADDRESS in the environment, else from the
# same variable in SF_ENV_FILE (strict KEY=VALUE, grepped, never sourced). It is an IPv4
# address, optionally with ":53" (the sink listens on port 53 only). When it is unset the
# script adds nothing and says so, which keeps v1 behaviour on upgrade.
#
# Needs from host-setup.sh: say, fail, run, is_ipv4, env_file_value, PROXY_HOST_CHAIN.

DNS_SINK_VAR="SANDFORT_EGRESS_DNS_SINK_ADDRESS"
DNS_SINK_PORT="53"
DNS_SINK=""  # the sink address admitted on the egress bridge (set by resolve_dns_sink)
DNS_SINK_SOURCE=""  # where the address came from (named in the output)

# dns_sink_octets_valid ADDR: true when every octet of a dotted quad is at most 255.
dns_sink_octets_valid() {
    old_ifs="$IFS"
    IFS=.
    # shellcheck disable=SC2086 # the address is deliberately split into its octets
    set -- $1
    IFS="$old_ifs"
    for octet in "$@"; do
        [ "${#octet}" -le 3 ] || return 1
        [ "$octet" -le 255 ] || return 1
    done
}

# parse_dns_sink RAW: set DNS_SINK from "addr" or "addr:53"; any other form dies.
parse_dns_sink() {
    addr="$1"
    case "$addr" in
        *:*:*) fail "$DNS_SINK_VAR must be an IPv4 address (optionally addr:53): $addr" ;;
        *:*)
            addr_port="${addr##*:}"
            addr="${addr%:*}"
            [ "$addr_port" = "$DNS_SINK_PORT" ] \
                || fail "$DNS_SINK_VAR port must be $DNS_SINK_PORT (the sink binds only that): $1"
            ;;
    esac
    is_ipv4 "$addr" && dns_sink_octets_valid "$addr" \
        || fail "$DNS_SINK_VAR must be an IPv4 address (optionally addr:53): $1"
    DNS_SINK="$addr"
}

# resolve_dns_sink: set DNS_SINK (empty when unset). Called before any rule is written, so a
# malformed value dies with nothing half-applied.
resolve_dns_sink() {
    raw="${SANDFORT_EGRESS_DNS_SINK_ADDRESS:-}"
    DNS_SINK_SOURCE="$DNS_SINK_VAR in the environment"
    if [ -z "$raw" ]; then
        raw="$(env_file_value "$DNS_SINK_VAR")"
        DNS_SINK_SOURCE="$DNS_SINK_VAR in $ENV_FILE"
    fi
    if [ -z "$raw" ]; then
        DNS_SINK=""
        say "no DNS sink address ($DNS_SINK_VAR is unset): sandboxes on $EGRESS_NETWORK get no" \
            "DNS exception"
        return 0
    fi
    parse_dns_sink "$raw"
    say "DNS sink $DNS_SINK (source: $DNS_SINK_SOURCE)"
}

# add_dns_sink_exception CHAIN: the single exception, udp and tcp 53 to the sink address.
# Does nothing when no sink is configured.
add_dns_sink_exception() {
    [ -n "$DNS_SINK" ] || return 0
    run iptables -A "$1" -p udp -d "$DNS_SINK" --dport "$DNS_SINK_PORT" -j RETURN
    run iptables -A "$1" -p tcp -d "$DNS_SINK" --dport "$DNS_SINK_PORT" -j RETURN
}
