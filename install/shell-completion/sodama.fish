# sodama fish completion（由 `sodama completion fish` 生成）
complete -c sodama -f
complete -c sodama -n __fish_use_subcommand -a "validate export-config extract-routing status reload suspend resume metrics sub-parse sysdump trace dns-bench completion"
complete -c sodama -l ebpf
complete -c sodama -l lan
complete -c sodama -l wan
complete -c sodama -l dual
complete -c sodama -l dae0
complete -c sodama -l dae0peer
complete -c sodama -l daens
complete -c sodama -l tproxy-port
complete -c sodama -l rules
complete -c sodama -l config
complete -c sodama -l strict-config
complete -c sodama -l status-socket
complete -c sodama -l log-file
complete -c sodama -l watch-config
complete -c sodama -l dialer
complete -c sodama -l relay-idle-timeout
complete -c sodama -l dial-timeout
complete -c sodama -l dial-mode
complete -c sodama -l sniffing-timeout-ms
complete -c sodama -l sniff-punt
complete -c sodama -l disable-timestamp
complete -c sodama -l disable-pidfile
complete -c sodama -l subscribe
complete -c sodama -l geodata-dir
complete -c sodama -l group
complete -c sodama -l listen-socks
complete -c sodama -l udp-idle-timeout
complete -c sodama -l forward
complete -c sodama -l offload
complete -c sodama -l link-hdr
complete -c sodama -l xdp
complete -c sodama -l no-splice
complete -c sodama -l ebpf-debug
complete -c sodama -l ktls
complete -c sodama -l max-conns
complete -c sodama -l dns-upstream
complete -c sodama -l dump
complete -c sodama -l compile-dump
complete -c sodama -l proxy
complete -c sodama -s h -l help -d "显示帮助"
