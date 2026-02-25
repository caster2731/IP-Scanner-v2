"""
非同期スキャナーエンジン
aiohttp を使用して高速にIPアドレスをスキャンし、Webサービスを発見する。
脆弱性スキャンと指定IPスキャンにも対応。
"""

import asyncio
import aiohttp
import ssl
import json
import time
import re
import socket
import ipaddress
from datetime import datetime
from ip_generator import generate_random_ip
from database import save_result
from screenshot import take_screenshot
from vuln_scanner import run_vuln_scan, summarize_vulns

# スキャンの状態を管理する辞書
scan_state = {
    "running": False,
    "total_scanned": 0,
    "total_found": 0,
    "current_rate": 0,     # 現在のスキャン速度（/秒）
    "start_time": None,
    "mode": "random",       # "random" or "target"
    "target_total": 0,      # 指定IPモード時の合計ターゲット数
    "target_done": 0,       # 指定IPモード時の完了数
}

# WebSocket接続のリスト（リアルタイム通知用）
ws_connections: list = []


def reset_scan_state():
    """スキャン状態をリセットする"""
    scan_state["running"] = False
    scan_state["total_scanned"] = 0
    scan_state["total_found"] = 0
    scan_state["current_rate"] = 0
    scan_state["start_time"] = None
    scan_state["mode"] = "random"
    scan_state["target_total"] = 0
    scan_state["target_done"] = 0


async def extract_title(html: str) -> str:
    """HTMLからtitleタグを抽出する"""
    if not html:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        title = match.group(1).strip()
        # HTMLエンティティを簡易デコード
        title = title.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        title = title.replace("&quot;", '"').replace("&#39;", "'")
        # 長すぎるタイトルは切り詰め
        return title[:200] if len(title) > 200 else title
    return ""


async def get_ssl_info(ip: str, port: int) -> dict:
    """SSL証明書情報を取得する"""
    ssl_info = {"issuer": None, "expiry": None, "domain": None}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx),
            timeout=5
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            cert = ssl_obj.getpeercert()
            if cert:
                # 発行者
                issuer = cert.get("issuer", ())
                if issuer:
                    for item in issuer:
                        for key, val in item:
                            if key == "organizationName":
                                ssl_info["issuer"] = val
                                break
                # 有効期限
                ssl_info["expiry"] = cert.get("notAfter")
                # ドメイン名
                subject = cert.get("subject", ())
                if subject:
                    for item in subject:
                        for key, val in item:
                            if key == "commonName":
                                ssl_info["domain"] = val
                                break
                # SANからドメイン取得
                san = cert.get("subjectAltName", ())
                if san and not ssl_info["domain"]:
                    for typ, val in san:
                        if typ == "DNS":
                            ssl_info["domain"] = val
                            break
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return ssl_info


async def reverse_dns_lookup(ip: str) -> str | None:
    """IPアドレスから逆引きDNSでホスト名を取得する"""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=3
        )
        return result[0]  # (hostname, aliases, addresses)
    except Exception:
        return None


async def get_country_info(session: aiohttp.ClientSession, ip: str) -> dict:
    """ip-api.comを使ってIPアドレスの国籍情報を取得する"""
    info = {"country": None, "country_code": None}
    try:
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode",
            timeout=aiohttp.ClientTimeout(total=5),
            ssl=False
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                info["country"] = data.get("country")
                info["country_code"] = data.get("countryCode")
    except Exception:
        pass
    return info


async def scan_single_ip(session: aiohttp.ClientSession, ip: str, port: int,
                         take_screenshots: bool = True,
                         run_vuln_check: bool = True) -> dict | None:
    """
    1つのIP:ポートをスキャンする。
    Webサービスが見つかった場合、結果を辞書で返す。
    """
    # プロトコル判定
    protocol = "https" if port in (443, 8443) else "http"
    url = f"{protocol}://{ip}:{port}"

    start_time = time.time()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(
            total=8, connect=3, sock_read=5
        ), allow_redirects=True, ssl=False) as response:
            elapsed_ms = int((time.time() - start_time) * 1000)

            # レスポンスボディを取得（最大1MB）
            try:
                body = await response.text(encoding="utf-8", errors="ignore")
                body = body[:1_000_000]
            except Exception:
                body = ""

            # ページタイトルの抽出
            title = await extract_title(body)

            # サーバー情報
            server = response.headers.get("Server", "")

            # 重要なレスポンスヘッダーを収集
            important_headers = {}
            for h in ["Server", "X-Powered-By", "Content-Type", "X-Frame-Options",
                       "Strict-Transport-Security", "X-Content-Type-Options",
                       "Content-Security-Policy", "X-XSS-Protection",
                       "Referrer-Policy", "Permissions-Policy"]:
                val = response.headers.get(h)
                if val:
                    important_headers[h] = val

            # SSL証明書情報（HTTPSの場合のみ）
            ssl_info = {"issuer": None, "expiry": None, "domain": None}
            if protocol == "https":
                ssl_info = await get_ssl_info(ip, port)

            # 逆引きDNS + 国籍取得（並行実行で高速化）
            hostname_task = reverse_dns_lookup(ip)
            country_task = get_country_info(session, ip)
            hostname, country_info = await asyncio.gather(
                hostname_task, country_task, return_exceptions=True
            )
            if isinstance(hostname, Exception):
                hostname = None
            if isinstance(country_info, Exception):
                country_info = {"country": None, "country_code": None}

            # 脆弱性スキャン
            vuln_data = None
            vuln_count = 0
            vuln_max_risk = "info"
            if run_vuln_check:
                try:
                    findings = await run_vuln_scan(
                        session, url,
                        dict(response.headers),
                        body, ssl_info, protocol
                    )
                    if findings:
                        vuln_summary = summarize_vulns(findings)
                        vuln_data = json.dumps(findings, ensure_ascii=False)
                        vuln_count = vuln_summary["total"]
                        vuln_max_risk = vuln_summary["max_risk"]
                except Exception:
                    pass

            # スクリーンショット取得
            screenshot_path = None
            if take_screenshots and response.status < 400:
                screenshot_path = await take_screenshot(url, ip, port)

            result = {
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "status_code": response.status,
                "title": title,
                "server": server,
                "ssl_issuer": ssl_info["issuer"],
                "ssl_expiry": ssl_info["expiry"],
                "ssl_domain": ssl_info["domain"],
                "hostname": hostname,
                "country": country_info.get("country"),
                "country_code": country_info.get("country_code"),
                "screenshot_path": screenshot_path,
                "response_time_ms": elapsed_ms,
                "headers": json.dumps(important_headers, ensure_ascii=False),
                "vulnerabilities": vuln_data,
                "vuln_count": vuln_count,
                "vuln_max_risk": vuln_max_risk,
                "scanned_at": datetime.now().isoformat(),
            }

            return result

    except (aiohttp.ClientError, asyncio.TimeoutError, OSError, Exception):
        return None


async def notify_ws(data: dict):
    """WebSocket接続にデータを送信する"""
    if not ws_connections:
        return
    message = json.dumps(data, ensure_ascii=False)
    disconnected = []
    for ws in ws_connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.append(ws)
    for ws in disconnected:
        ws_connections.remove(ws)


def parse_target_ips(target_input: str) -> list[str]:
    """
    ユーザー入力からIPアドレスリストを生成する。
    対応形式:
      - 単一IP: "1.1.1.1"
      - カンマ区切り: "1.1.1.1, 8.8.8.8"
      - CIDR: "192.168.1.0/24"
      - URL: "http://example.com" / "https://example.com:8080/path"
      - ドメイン名: "example.com"
      - 改行区切り
      - 混合: 上記を自由に組み合わせ可能
    """
    import socket
    from urllib.parse import urlparse

    ips = []
    resolved_cache = {}  # DNSキャッシュ（同じドメインの重複解決を防ぐ）

    # カンマ、改行で分割（スペースはURL内に含まれないのでOK）
    parts = re.split(r'[,\n]+', target_input.strip())
    for part in parts:
        part = part.strip()
        if not part:
            continue

        # URLかどうか判定（http:// or https:// で始まる場合）
        if part.startswith("http://") or part.startswith("https://"):
            try:
                parsed = urlparse(part)
                hostname = parsed.hostname
                if hostname:
                    # ホスト名からIPを解決
                    resolved_ip = _resolve_hostname(hostname, resolved_cache)
                    if resolved_ip:
                        ips.append(resolved_ip)
                continue
            except Exception:
                continue

        # CIDR表記
        try:
            if '/' in part and not '.' not in part:
                pass  # ドメイン名のパス部分は無視
            if '/' in part:
                # まずCIDRとして試す
                network = ipaddress.IPv4Network(part, strict=False)
                if network.prefixlen < 16:
                    continue
                for host in network.hosts():
                    ips.append(str(host))
                continue
        except (ipaddress.AddressValueError, ValueError):
            pass

        # 単一IP
        try:
            ip = ipaddress.IPv4Address(part)
            ips.append(str(ip))
            continue
        except (ipaddress.AddressValueError, ValueError):
            pass

        # ドメイン名として試行（上記のどれにも該当しない場合）
        # ポート付きドメイン（example.com:8080）にも対応
        hostname = part.split(":")[0] if ":" in part else part
        # ドメイン名らしいか簡易チェック（ドットを含む英数字）
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$', hostname):
            resolved_ip = _resolve_hostname(hostname, resolved_cache)
            if resolved_ip:
                ips.append(resolved_ip)

    return ips


def _resolve_hostname(hostname: str, cache: dict) -> str | None:
    """ホスト名をDNS解決してIPアドレスを返す（キャッシュ付き）"""
    import socket

    if hostname in cache:
        return cache[hostname]

    try:
        ip = socket.gethostbyname(hostname)
        cache[hostname] = ip
        return ip
    except socket.gaierror:
        cache[hostname] = None
        return None


async def scan_worker(ports: list[int], take_screenshots: bool = True,
                      run_vuln_check: bool = True):
    """
    ランダムスキャンワーカー。
    ランダムIPを継続的に生成してスキャンし、結果をDBに保存してWebSocketで通知する。
    """
    connector = aiohttp.TCPConnector(
        limit=200,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=True,
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        rate_counter = 0
        rate_start = time.time()

        while scan_state["running"]:
            tasks = []
            batch_size = 50

            for _ in range(batch_size):
                if not scan_state["running"]:
                    break
                ip = generate_random_ip()
                for port in ports:
                    tasks.append(scan_single_ip(
                        session, ip, port, take_screenshots, run_vuln_check
                    ))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if not scan_state["running"]:
                    break
                if isinstance(result, dict) and result is not None:
                    result_id = await save_result(result)
                    result["id"] = result_id
                    scan_state["total_found"] += 1
                    await notify_ws({"type": "result", "data": result})

            scanned_count = len(tasks)
            scan_state["total_scanned"] += scanned_count
            rate_counter += scanned_count

            elapsed = time.time() - rate_start
            if elapsed >= 1.0:
                scan_state["current_rate"] = round(rate_counter / elapsed)
                rate_counter = 0
                rate_start = time.time()
                await notify_ws({
                    "type": "status",
                    "data": {
                        "running": scan_state["running"],
                        "total_scanned": scan_state["total_scanned"],
                        "total_found": scan_state["total_found"],
                        "current_rate": scan_state["current_rate"],
                        "mode": scan_state["mode"],
                    }
                })

            await asyncio.sleep(0.01)

    await notify_ws({
        "type": "status",
        "data": {
            "running": False,
            "total_scanned": scan_state["total_scanned"],
            "total_found": scan_state["total_found"],
            "current_rate": 0,
            "mode": scan_state["mode"],
        }
    })


async def scan_target_worker(target_ips: list[str], ports: list[int],
                              take_screenshots: bool = True,
                              run_vuln_check: bool = True):
    """
    指定IPスキャンワーカー。
    指定されたIPリストを順にスキャンする。
    """
    scan_state["target_total"] = len(target_ips) * len(ports)
    scan_state["target_done"] = 0

    connector = aiohttp.TCPConnector(
        limit=100,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=True,
    )

    async with aiohttp.ClientSession(connector=connector) as session:
        rate_counter = 0
        rate_start = time.time()

        # バッチに分けて処理
        batch_size = 20
        all_tasks = [(ip, port) for ip in target_ips for port in ports]

        for i in range(0, len(all_tasks), batch_size):
            if not scan_state["running"]:
                break

            batch = all_tasks[i:i + batch_size]
            tasks = [
                scan_single_ip(session, ip, port, take_screenshots, run_vuln_check)
                for ip, port in batch
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if not scan_state["running"]:
                    break
                scan_state["target_done"] += 1

                if isinstance(result, dict) and result is not None:
                    result_id = await save_result(result)
                    result["id"] = result_id
                    scan_state["total_found"] += 1
                    await notify_ws({"type": "result", "data": result})

            scanned_count = len(batch)
            scan_state["total_scanned"] += scanned_count
            rate_counter += scanned_count

            elapsed = time.time() - rate_start
            if elapsed >= 1.0:
                scan_state["current_rate"] = round(rate_counter / elapsed)
                rate_counter = 0
                rate_start = time.time()

            # 進捗通知
            await notify_ws({
                "type": "status",
                "data": {
                    "running": scan_state["running"],
                    "total_scanned": scan_state["total_scanned"],
                    "total_found": scan_state["total_found"],
                    "current_rate": scan_state["current_rate"],
                    "mode": "target",
                    "target_total": scan_state["target_total"],
                    "target_done": scan_state["target_done"],
                }
            })

            await asyncio.sleep(0.01)

    # スキャン完了
    scan_state["running"] = False
    await notify_ws({
        "type": "status",
        "data": {
            "running": False,
            "total_scanned": scan_state["total_scanned"],
            "total_found": scan_state["total_found"],
            "current_rate": 0,
            "mode": "target",
            "target_total": scan_state["target_total"],
            "target_done": scan_state["target_done"],
        }
    })
