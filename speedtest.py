#!/usr/bin/env python3
"""Cloudflare 优选 IP 测速：从官方 IP 段采样 -> 测 TCP 延迟 -> 查定位（loc）
-> 对延迟最好的测下载速度。优先保留定位美国（loc=US）的节点，
方便美区 AI 服务（AI 认美国出口）。
只用 Python 标准库。输出 preferred_ips.txt（ip,loc,colo,延迟ms,速度kbps）。
"""
import ipaddress
import random
import re
import socket
import ssl
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CF_V4_URL = "https://www.cloudflare.com/ips-v4"
SAMPLE_PER_CIDR = 25
CONNECT_TIMEOUT = 2.0
LATENCY_ROUNDS = 2
TRACE_POOL = 80
TOP_BY_LATENCY = 40
FINAL_COUNT = 12
SPEED_BYTES = 1_000_000
SPEED_TIMEOUT = 8

ERRORS = []
def note_error(phase, ip, exc):
    if len(ERRORS) < 8:
        ERRORS.append((phase, ip, f"{type(exc).__name__}: {exc}"))


def fetch_cidrs():
    req = urllib.request.Request(CF_V4_URL, headers={"User-Agent": "cf-preferred/1.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return [l.strip() for l in r.read().decode().splitlines() if l.strip()]


def sample_ips(cidrs):
    ips = []
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c)
        except ValueError:
            continue
        hosts = list(net.hosts())
        if not hosts:
            continue
        k = min(SAMPLE_PER_CIDR, len(hosts))
        ips.extend(str(ip) for ip in random.sample(hosts, k))
    random.shuffle(ips)
    return ips


def tcp_latency(ip, port=443):
    best = None
    for _ in range(LATENCY_ROUNDS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        t0 = time.monotonic()
        try:
            s.connect((ip, port))
            dt = (time.monotonic() - t0) * 1000
            best = dt if best is None else min(best, dt)
        except OSError:
            return None
        finally:
            s.close()
    return best


def dechunk(data):
    out = b""
    i = 0
    while True:
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(data[i:j].split(b";")[0].strip(), 16)
        except ValueError:
            break
        i = j + 2
        if size == 0:
            break
        out += data[i:i + size]
        i += size + 2
    return out


def https_via_ip(ip, sni_host, path, timeout=10, read_limit=3_000_000):
    s = socket.create_connection((ip, 443), timeout=timeout)
    ss = None
    try:
        ctx = ssl._create_unverified_context()
        ss = ctx.wrap_socket(s, server_hostname=sni_host)
        req = (f"GET {path} HTTP/1.1\r\n"
               f"Host: {sni_host}\r\n"
               f"User-Agent: cf-preferred/1.0\r\n"
               f"Connection: close\r\n\r\n")
        ss.sendall(req.encode())
        ss.settimeout(timeout)
        data = b""
        while True:
            try:
                chunk = ss.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if len(data) >= read_limit:
                break
        header, _, rest = data.partition(b"\r\n\r\n")
        if b"chunked" in header.lower():
            rest = dechunk(rest)
        return rest
    finally:
        if ss is not None:
            ss.close()
        else:
            s.close()


def cf_trace(ip):
    try:
        body = https_via_ip(ip, "www.cloudflare.com", "/cdn-cgi/trace",
                            timeout=8, read_limit=8192)
        loc = colo = None
        m = re.search(rb"loc=([A-Z]+)", body)
        if m:
            loc = m.group(1).decode()
        m = re.search(rb"colo=([A-Z]+)", body)
        if m:
            colo = m.group(1).decode()
        return loc, colo
    except Exception as e:
        note_error("trace", ip, e)
        return None, None


def dl_speed_kbps(ip):
    t0 = time.monotonic()
    try:
        body = https_via_ip(ip, "speed.cloudflare.com",
                            f"/__down?bytes={SPEED_BYTES}",
                            timeout=SPEED_TIMEOUT + 4,
                            read_limit=SPEED_BYTES + 65536)
        dt = time.monotonic() - t0
        n = len(body)
        if dt <= 0 or n == 0:
            return None
        return (n * 8 / 1000) / dt
    except Exception as e:
        note_error("speed", ip, e)
        return None


def main():
    print("获取 Cloudflare 官方 IP 段...", flush=True)
    cidrs = fetch_cidrs()
    print(f"共 {len(cidrs)} 个段", flush=True)
    print("对照：域名方式 HTTPS 下载（应成功）...", flush=True)
    try:
        ctx0 = ssl._create_unverified_context()
        req0 = urllib.request.Request(
            "https://speed.cloudflare.com/__down?bytes=1000",
            headers={"User-Agent": "cf-preferred/1.0"})
        with urllib.request.urlopen(req0, timeout=10, context=ctx0) as r0:
            n0 = len(r0.read())
        print(f"  域名 HTTPS 正常（{n0} 字节）", flush=True)
    except Exception as e:
        note_error("sanity-domain", "speed.cloudflare.com", e)
        print(f"  域名 HTTPS 也失败：{type(e).__name__}: {e}", flush=True)
    ips = sample_ips(cidrs)
    print(f"抽样 {len(ips)} 个 IP 测延迟...", flush=True)
    lat = {}
    with ThreadPoolExecutor(max_workers=50) as ex:
        for ip, ms in zip(ips, ex.map(tcp_latency, ips)):
            if ms is not None:
                lat[ip] = ms
    print(f"延迟可用 {len(lat)} 个", flush=True)
    if not lat:
        raise SystemExit("没有可用 IP，检查网络后重试")
    cands = sorted(lat, key=lat.get)[:TRACE_POOL]
    print(f"取延迟最好的 {len(cands)} 个查定位...", flush=True)
    loc_of, colo_of = {}, {}
    with ThreadPoolExecutor(max_workers=30) as ex:
        for ip, (loc, colo) in zip(cands, ex.map(cf_trace, cands)):
            loc_of[ip] = loc
            colo_of[ip] = colo or ""
    ok_loc = sum(1 for ip in cands if loc_of.get(ip))
    us = [ip for ip in cands if loc_of.get(ip) == "US"]
    print(f"定位成功 {ok_loc} 个，其中定位美国 {len(us)} 个", flush=True)
    ranked_cands = sorted(cands, key=lambda ip: (0 if loc_of.get(ip) == "US" else 1, lat[ip]))
    top = ranked_cands[:TOP_BY_LATENCY]
    print(f"取前 {len(top)} 个（美国优先）测下载速度...", flush=True)
    spd = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        for ip, kbps in zip(top, ex.map(dl_speed_kbps, top)):
            if kbps is not None:
                spd[ip] = kbps
    print(f"速度可用 {len(spd)} 个", flush=True)
    if ERRORS:
        print("---- 失败诊断（前几条）----", flush=True)
        for phase, ip, msg in ERRORS:
            print(f"  [{phase}] {ip} -> {msg}", flush=True)
    if not spd:
        raise SystemExit("速度测试全部失败，检查网络后重试")
    ranked = sorted(spd, key=lambda ip: (0 if loc_of.get(ip) == "US" else 1, lat[ip], -spd[ip]))[:FINAL_COUNT]
    with open("preferred_ips.txt", "w") as f:
        for ip in ranked:
            f.write(f"{ip},{loc_of.get(ip) or '??'},{colo_of.get(ip) or ''},{lat[ip]:.1f},{spd[ip]:.0f}\n")
    print(f"写入 preferred_ips.txt，共 {len(ranked)} 个优选 IP", flush=True)
    for ip in ranked:
        print(f"  {ip} [{loc_of.get(ip) or '??'}] 延迟 {lat[ip]:.0f}ms  速度 {spd[ip]:.0f}kbps")


if __name__ == "__main__":
    main()
