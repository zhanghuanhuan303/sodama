#!/usr/bin/env python3
"""Pick candidate nodes from a decoded subscription; never prints credentials.

Usage:
  python3 probe-nodes.py list  /tmp/sub2.dec.txt          # safe listing
  python3 probe-nodes.py pick  /tmp/sub2.dec.txt IDX out  # write one node URL to `out`
"""
import sys, urllib.parse


def parse(line):
    line = line.strip()
    if not line:
        return None
    p = urllib.parse.urlsplit(line)
    if not p.scheme:
        return None
    q = dict(urllib.parse.parse_qsl(p.query))
    return {
        "scheme": p.scheme,
        "host": p.hostname,
        "port": p.port,
        "name": urllib.parse.unquote(p.fragment or ""),
        "security": q.get("security", ""),
        "flow": q.get("flow", ""),
        "url": line,
    }


def main():
    mode, path = sys.argv[1], sys.argv[2]
    with open(path) as f:
        nodes = [n for n in (parse(l) for l in f) if n]
    if mode == "list":
        for i, n in enumerate(nodes):
            print(f"{i:3d} {n['scheme']:8s} {n['host']}:{n['port']} sec={n['security'] or '-':6s} "
                  f"flow={n['flow'] or '-':16s} {n['name'][:48]}")
    elif mode == "pick":
        idx, out = int(sys.argv[3]), sys.argv[4]
        n = nodes[idx]
        with open(out, "w") as f:
            f.write(n["url"])
        print(f"wrote node {idx}: {n['scheme']} {n['host']}:{n['port']} sec={n['security'] or '-'} to {out}")


if __name__ == "__main__":
    main()
