#!/usr/bin/env python3
"""根据 preferred_ips.txt 生成订阅文件：
- sub.txt      ：vless 链接列表（把节点地址换成优选 IP）
- clash.yaml   ：Clash 订阅，自带分流（国内直连、其他走代理）
- singbox.json ：sing-box 配置，自带分流（国内直连、其他走代理）

节点模板从 node_template.txt 读取：放一条 vless:// 链接，
只替换地址，其余参数（uuid/tls/sni/ws-path 等）原样保留。
"""
import json
import urllib.parse

TEMPLATE_FILE = "node_template.txt"


def load_template_raw():
    with open(TEMPLATE_FILE) as f:
        line = f.read().strip().splitlines()[0].strip()
    return line if line.startswith("vless://") else None


def parse_vless(uri):
    u = urllib.parse.urlparse(uri)
    q = dict(urllib.parse.parse_qsl(u.query))
    return {
        "uuid": u.username,
        "port": u.port or 443,
        "params": q,
        "name": urllib.parse.unquote(u.fragment) or "CF优选",
    }


def node_name(tpl, loc, idx):
    return f"{tpl['name']}-CF{idx:02d}-{loc}"


def build_vless(tpl, ip, name):
    q = urllib.parse.urlencode(tpl["params"])
    return f"vless://{tpl['uuid']}@{ip}:{tpl['port']}?{q}#{urllib.parse.quote(name)}"


def clash_proxy(tpl, ip, name):
    p = tpl["params"]
    lines = [
        f"  - name: {name}",
        "    type: vless",
        f"    server: {ip}",
        f"    port: {tpl['port']}",
        f"    uuid: {tpl['uuid']}",
    ]
    if p.get("security") == "tls":
        lines.append("    tls: true")
        if p.get("sni"):
            lines.append(f"    servername: {p['sni']}")
        if p.get("fp"):
            lines.append(f"    client-fingerprint: {p['fp']}")
    if p.get("type", "tcp") == "ws":
        lines.append("    network: ws")
        ws_opts = []
        if p.get("path"):
            ws_opts.append(f"      path: {urllib.parse.unquote(p['path'])}")
        if p.get("host"):
            ws_opts.append("      headers:")
            ws_opts.append(f"        Host: {p['host']}")
        if ws_opts:
            lines.append("    ws-opts:")
            lines.extend(ws_opts)
    return "\n".join(lines)


def write_clash(tpl, nodes):
    names = [n["name"] for n in nodes]
    out = ["proxies:"]
    for n in nodes:
        out.append(clash_proxy(tpl, n["ip"], n["name"]))
    out += [
        "",
        "proxy-groups:",
        "  - name: \U0001f680 CF优选",
        "    type: url-test",
        "    url: http://www.gstatic.com/generate_204",
        "    interval: 300",
        "    tolerance: 50",
        "    proxies:",
    ]
    out += [f"      - {n}" for n in names]
    out += [
        "",
        "# 分流：国内直连，其他走代理",
        "rule-providers:",
        "  direct:",
        "    type: http",
        "    behavior: domain",
        "    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
        "    path: ./ruleset/direct.yaml",
        "    interval: 86400",
        "  proxy:",
        "    type: http",
        "    behavior: domain",
        "    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
        "    path: ./ruleset/proxy.yaml",
        "    interval: 86400",
        "  gfw:",
        "    type: http",
        "    behavior: domain",
        "    url: https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
        "    path: ./ruleset/gfw.yaml",
        "    interval: 86400",
        "rules:",
        "  - RULE-SET,direct,DIRECT",
        "  - RULE-SET,proxy,\U0001f680 CF优选",
        "  - RULE-SET,gfw,\U0001f680 CF优选",
        "  - GEOIP,CN,DIRECT",
        "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "  - MATCH,\U0001f680 CF优选",
        "",
    ]
    with open("clash.yaml", "w") as f:
        f.write("\n".join(out))


def write_singbox(tpl, nodes):
    p = tpl["params"]
    outbounds = [{"type": "direct", "tag": "DIRECT"}]
    tags = []
    for n in nodes:
        ob = {
            "type": "vless",
            "tag": n["name"],
            "server": n["ip"],
            "server_port": tpl["port"],
            "uuid": tpl["uuid"],
        }
        if p.get("security") == "tls":
            tls = {"enabled": True}
            if p.get("sni"):
                tls["server_name"] = p["sni"]
            if p.get("fp"):
                tls["utls"] = {"enabled": True, "fingerprint": p["fp"]}
            ob["tls"] = tls
        if p.get("type", "tcp") == "ws":
            tr = {"type": "ws"}
            if p.get("path"):
                tr["path"] = urllib.parse.unquote(p["path"])
            if p.get("host"):
                tr["headers"] = {"Host": p["host"]}
            ob["transport"] = tr
        outbounds.append(ob)
        tags.append(n["name"])
    outbounds.append({
        "type": "urltest",
        "tag": "\U0001f680 CF优选",
        "outbounds": tags,
        "url": "http://www.gstatic.com/generate_204",
        "interval": "5m",
        "tolerance": 50,
    })
    cfg = {
        "outbounds": outbounds,
        "route": {
            "rules": [
                {"rule_set": ["geosite-cn", "geoip-cn"], "outbound": "DIRECT"},
            ],
            "rule_set": [
                {"tag": "geosite-cn", "type": "remote", "format": "binary",
                 "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
                 "download_detour": "\U0001f680 CF优选"},
                {"tag": "geoip-cn", "type": "remote", "format": "binary",
                 "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
                 "download_detour": "\U0001f680 CF优选"},
            ],
            "final": "\U0001f680 CF优选",
            "auto_detect_interface": True,
        },
    }
    with open("singbox.json", "w") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def main():
    try:
        with open("preferred_ips.txt") as f:
            rows = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        raise SystemExit("找不到 preferred_ips.txt，先跑 speedtest.py")
    nodes = []
    for r in rows:
        parts = r.split(",")
        ip = parts[0]
        loc = parts[1] if len(parts) > 1 else "??"
        nodes.append({"ip": ip, "loc": loc})

    raw = load_template_raw()
    if not raw:
        print(f"未找到 {TEMPLATE_FILE}（放一条 vless:// 链接进去），只生成 IP 列表订阅")
        with open("sub.txt", "w") as f:
            f.write("\n".join(n["ip"] for n in nodes) + "\n")
        return

    tpl = parse_vless(raw)
    for i, n in enumerate(nodes):
        n["name"] = node_name(tpl, n["loc"], i + 1)

    with open("sub.txt", "w") as f:
        f.write("\n".join(build_vless(tpl, n["ip"], n["name"]) for n in nodes) + "\n")

    write_clash(tpl, nodes)
    write_singbox(tpl, nodes)
    print(f"生成 sub.txt / clash.yaml / singbox.json，共 {len(nodes)} 个节点（美国优先）")


if __name__ == "__main__":
    main()
