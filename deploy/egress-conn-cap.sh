# sandfort egress connection cap: the host firewall part. Sourced by host-setup.sh, not run alone.
#
# The per-sandbox connection limit of the egress proxy covers only sandboxes with an egress
# allowlist. A sandbox on the open network (sf-net, bridge sf-br0) has no limit of its own, so
# one runaway sandbox could fill the host's shared conntrack table. This file adds one rule to
# SANDFORT-EGRESS, after the private-range rejects and before the final RETURN: a new flow
# (conntrack state NEW) from a sandbox address is sent to SANDFORT-CONNCAP once that address
# already holds SF_SANDBOX_CONN_LIMIT tracked flows. SANDFORT-CONNCAP logs (one line a minute,
# burst 5, host-wide, prefix "sandfort-conncap:"), then answers TCP with a reset (the sandbox
# sees "Connection refused") and everything else with ICMP admin-prohibited. REJECT, not DROP,
# so the client fails at once instead of retrying SYNs until its own timeout.
#
# Scope. The rule carries "-i" of the sandbox bridge (sf-br0), so it covers sf-net only. Image
# builds on docker0 and sandboxes on sf-egress-net (sf-br1) get no host cap: the egress proxy
# bounds only concurrent tunnels on sf-br1, not the rate of new flows or DNS packets to the
# sink, so neither bridge has a conntrack bound here. The key is the sandbox address: every sandbox has its own address on sf-net and
# MASQUERADE runs after FORWARD, so no address list is needed. TCP, UDP and ICMP flows count
# together, and IPv4 (mask 32) and IPv6 (mask 128) are counted separately. Half-open, closing
# and recent UDP flows (DNS included) count until conntrack expires them.
#
# SF_SANDBOX_CONN_LIMIT (environment only) is the limit: a whole number from 1 to 100000, default
# 512, empty means the default, 0 turns the cap off (the chain is then not referenced). Anything
# else dies before any rule is written. The kernel needs xt_connlimit, xt_limit and xt_LOG: a
# probe chain checks them before any real chain is flushed (not in a dry run).
#
# Needs from host-setup.sh: say, fail, run, DRY_RUN, EGRESS_CHAIN, SANDBOX_IFACE.

CONN_CAP_VAR="SF_SANDBOX_CONN_LIMIT"
CONN_CAP_DEFAULT="512"
CONN_CAP_MAX="100000"
CONN_CAP_CHAIN="SANDFORT-CONNCAP"
CONN_CAP_PROBE_CHAIN="SANDFORT-CONNCAP-PROBE"
CONN_CAP=""  # the limit in force (set by resolve_conn_cap; 0 means off)

# resolve_conn_cap: set CONN_CAP from SF_SANDBOX_CONN_LIMIT. Called before any rule is written,
# so a malformed value dies with nothing half-applied.
resolve_conn_cap() {
    cc_raw="${SF_SANDBOX_CONN_LIMIT:-}"
    if [ -z "$cc_raw" ]; then
        cc_raw="$CONN_CAP_DEFAULT"
    fi
    cc_what="$CONN_CAP_VAR must be a whole number from 0 to $CONN_CAP_MAX (0 turns the cap off)"
    case "$cc_raw" in
        "" | *[!0-9]*) fail "$cc_what: $cc_raw" ;;
    esac
    case "$cc_raw" in
        0) ;;
        0*) fail "$cc_what: $cc_raw" ;;
    esac
    [ "${#cc_raw}" -le 6 ] || fail "$cc_what: $cc_raw"
    [ "$cc_raw" -le "$CONN_CAP_MAX" ] || fail "$cc_what: $cc_raw"
    CONN_CAP="$cc_raw"
}

# cc_probe_tool TOOL MASK: build a throwaway chain with the connlimit and LOG rules, then always
# remove it. True when the kernel accepted both rules.
cc_probe_tool() {
    cc_tool="$1"
    cc_mask="$2"
    cc_ok=1
    "$cc_tool" -F "$CONN_CAP_PROBE_CHAIN" >/dev/null 2>&1 || true
    "$cc_tool" -X "$CONN_CAP_PROBE_CHAIN" >/dev/null 2>&1 || true
    "$cc_tool" -N "$CONN_CAP_PROBE_CHAIN" || cc_ok=0
    "$cc_tool" -A "$CONN_CAP_PROBE_CHAIN" -m conntrack --ctstate NEW -m connlimit \
        --connlimit-above 1 --connlimit-mask "$cc_mask" --connlimit-saddr -j RETURN \
        || cc_ok=0
    "$cc_tool" -A "$CONN_CAP_PROBE_CHAIN" -m limit --limit 1/min --limit-burst 5 \
        -j LOG --log-prefix "sandfort-conncap:" || cc_ok=0
    "$cc_tool" -F "$CONN_CAP_PROBE_CHAIN" >/dev/null 2>&1 || true
    "$cc_tool" -X "$CONN_CAP_PROBE_CHAIN" >/dev/null 2>&1 || true
    [ "$cc_ok" = "1" ]
}

# probe_conn_cap: die before any flush when the kernel refuses the cap rules. Direct calls, not
# run: a dry run has nothing to probe and says so.
probe_conn_cap() {
    if [ "$CONN_CAP" = "0" ]; then
        return 0
    fi
    if [ "$DRY_RUN" = "1" ]; then
        say "connlimit probe skipped (dry run)"
        return 0
    fi
    cc_fix="connlimit, limit or LOG rule refused by the kernel: run modprobe xt_connlimit"
    cc_fix="$cc_fix (and xt_limit, xt_LOG), or set $CONN_CAP_VAR=0 to run without the cap"
    cc_probe_tool iptables 32 || fail "iptables $cc_fix"
    if command -v ip6tables >/dev/null 2>&1; then
        cc_probe_tool ip6tables 128 || fail "ip6tables $cc_fix"
    fi
}

# cc_build_chain TOOL REJECT_TYPE: create or flush the cap chain and fill it. Never removes it.
cc_build_chain() {
    cc_tool="$1"
    if "$cc_tool" -n -L "$CONN_CAP_CHAIN" >/dev/null 2>&1; then
        run "$cc_tool" -F "$CONN_CAP_CHAIN"
    else
        run "$cc_tool" -N "$CONN_CAP_CHAIN"
    fi
    run "$cc_tool" -A "$CONN_CAP_CHAIN" -m limit --limit 1/min --limit-burst 5 \
        -j LOG --log-prefix "sandfort-conncap: " --log-level warning
    run "$cc_tool" -A "$CONN_CAP_CHAIN" -p tcp -j REJECT --reject-with tcp-reset
    run "$cc_tool" -A "$CONN_CAP_CHAIN" -j REJECT --reject-with "$2"
}

# build_conn_cap_chains: the cap chain in each family that has its tool. Does nothing when off.
build_conn_cap_chains() {
    if [ "$CONN_CAP" = "0" ]; then
        return 0
    fi
    cc_build_chain iptables icmp-admin-prohibited
    if command -v ip6tables >/dev/null 2>&1; then
        cc_build_chain ip6tables icmp6-adm-prohibited
    fi
}

# add_conn_cap TOOL CHAIN MASK: the one rule that counts flows per sandbox address.
add_conn_cap() {
    if [ "$CONN_CAP" = "0" ]; then
        return 0
    fi
    run "$1" -A "$2" -i "$SANDBOX_IFACE" -m conntrack --ctstate NEW -m connlimit \
        --connlimit-above "$CONN_CAP" --connlimit-mask "$3" --connlimit-saddr \
        -j "$CONN_CAP_CHAIN"
}

# report_conn_cap: one summary line, plus the conntrack table size when the kernel exposes it.
report_conn_cap() {
    if [ "$CONN_CAP" = "0" ]; then
        say "connection cap: off ($CONN_CAP_VAR=0)"
        return 0
    fi
    say "connection cap: $CONN_CAP tracked flows per sandbox address on $SANDBOX_IFACE" \
        "(IPv4 and IPv6 counted separately)"
    cc_dir="/proc/sys/net/netfilter"
    if [ -r "$cc_dir/nf_conntrack_max" ]; then
        cc_max="$(cat "$cc_dir/nf_conntrack_max" 2>/dev/null || true)"
        cc_used="$(cat "$cc_dir/nf_conntrack_count" 2>/dev/null || true)"
        say "conntrack: max ${cc_max:-unknown}, in use ${cc_used:-unknown}"
    fi
}
