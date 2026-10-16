# sodama bash completion（由 `sodama completion bash` 生成）
_sodama() {
    local cur prev
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local subcmds="validate export-config export extract-routing status reload suspend resume metrics sub-parse sysdump trace dns-bench completion"
    local flags="--ebpf --lan --wan --dual --dae0 --dae0peer --daens --tproxy-port --rules --config --strict-config --status-socket --log-file --watch-config --dialer --relay-idle-timeout --dial-timeout --dial-mode --sniffing-timeout-ms --sniff-punt --disable-timestamp --disable-pidfile --subscribe --geodata-dir --group --listen-socks --udp-idle-timeout --forward --offload --link-hdr --xdp --no-splice --ebpf-debug --ktls --max-conns --dns-upstream --dump --compile-dump --proxy --help"
    case "$prev" in
        --config|--rules|--ebpf|--log-file|--status-socket|--compile-dump|--listen-socks)
            COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
        --dial-mode) COMPREPLY=( $(compgen -W "ip domain domain+ domain++" -- "$cur") ); return ;;
        --link-hdr) COMPREPLY=( $(compgen -W "auto l2 l3" -- "$cur") ); return ;;
        --lan|--wan|--dual|--xdp|--dae0|--dae0peer)
            COMPREPLY=( $(compgen -W "$(ls /sys/class/net 2>/dev/null)" -- "$cur") ); return ;;
    esac
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") ); return
    fi
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$subcmds" -- "$cur") ); return
    fi
    case "${COMP_WORDS[1]}" in
        completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
        status) COMPREPLY=( $(compgen -W "--socket --cmd --json" -- "$cur") ) ;;
        reload|suspend|resume|metrics) COMPREPLY=( $(compgen -W "--socket" -- "$cur") ) ;;
        sysdump) COMPREPLY=( $(compgen -W "--socket --out" -- "$cur") ) ;;
        sub-parse) COMPREPLY=( $(compgen -W "--tag --timeout --limit --json" -- "$cur") ) ;;
        trace) COMPREPLY=( $(compgen -W "--seconds" -- "$cur") ) ;;
        dns-bench) COMPREPLY=( $(compgen -W "--config --names --tags --runs --rounds --concurrency --client" -- "$cur") ) ;;
        validate|export-config|extract-routing) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
    esac
}
complete -F _sodama sodama
