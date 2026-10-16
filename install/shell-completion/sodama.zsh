#compdef sodama
# sodama zsh completion（由 `sodama completion zsh` 生成）
_sodama() {
    local -a subcmds flags
    subcmds=(validate export-config extract-routing status reload suspend resume metrics sub-parse sysdump trace dns-bench completion)
    flags=(--ebpf --lan --wan --dual --dae0 --dae0peer --daens --tproxy-port --rules --config --strict-config --status-socket --log-file --watch-config --dialer --relay-idle-timeout --dial-timeout --dial-mode --sniffing-timeout-ms --sniff-punt --disable-timestamp --disable-pidfile --subscribe --geodata-dir --group --listen-socks --udp-idle-timeout --forward --offload --link-hdr --xdp --no-splice --ebpf-debug --ktls --max-conns --dns-upstream --dump --compile-dump --proxy --help)
    if (( CURRENT == 2 )); then
        _describe -t commands "子命令" subcmds
        _describe -t options "参数" flags
        return
    fi
    case "${words[2]}" in
        completion) _values "shell" bash zsh fish ;;
        status) _values "参数" --socket --cmd --json ;;
        reload|suspend|resume|metrics) _values "参数" --socket ;;
        sysdump) _values "参数" --socket --out ;;
        sub-parse) _values "参数" --tag --timeout --limit --json ;;
        trace) _values "参数" --seconds ;;
        dns-bench) _values "参数" --config --names --tags --runs --rounds --concurrency --client ;;
        validate|export-config|extract-routing) _files ;;
        *)
            case "${words[CURRENT]}" in
                -*) _describe -t options "参数" flags ;;
                *) _files ;;
            esac ;;
    esac
}
_sodama "$@"
