"""
通信秘匿化モジュール（ステルスモード）
Tor/SOCKS5プロキシ経由通信、User-Agentランダム化、リクエスト間隔ランダム化、
DNSリーク防止を一元管理する。
"""

import random
import asyncio
import time as _time
from typing import Optional

# ========== ステルスモード状態管理 ==========

stealth_state = {
    "enabled": False,               # ステルスモードの有効/無効
    "proxy_url": "socks5://127.0.0.1:9050",  # デフォルトはTor
    "delay_min": 0.1,               # リクエスト間の最小遅延（秒）
    "delay_max": 2.0,               # リクエスト間の最大遅延（秒）
    "randomize_ua": True,           # User-Agentランダム化の有効/無効
    "proxy_connected": False,       # プロキシ接続状態
}


# ========== User-Agent プール ==========
# リアルなブラウザのUser-Agent文字列（2025-2026年版）
USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    # Firefox (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    # Safari (iOS)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    # HTTPクライアント（ボット系ではないもの）
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
]


def get_random_ua() -> str:
    """ランダムなUser-Agent文字列を返す"""
    if stealth_state["enabled"] and stealth_state["randomize_ua"]:
        return random.choice(USER_AGENTS)
    # ステルス無効時は固定のUA（目立たない一般的なもの）
    return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def get_random_headers() -> dict:
    """ランダムなHTTPヘッダーを生成する（フィンガープリント回避）"""
    ua = get_random_ua()
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "ja,en-US;q=0.9,en;q=0.8",
            "de,en-US;q=0.9,en;q=0.7",
            "fr,en-US;q=0.9,en;q=0.7",
            "zh-CN,zh;q=0.9,en;q=0.7",
            "ko,en-US;q=0.9,en;q=0.7",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

    # ランダムにキャッシュ制御ヘッダーを追加（より自然に見せる）
    if random.random() > 0.5:
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
    if random.random() > 0.7:
        headers["DNT"] = "1"

    return headers


async def get_random_delay():
    """ステルスモード時にランダムな遅延を挿入する"""
    if stealth_state["enabled"]:
        delay = random.uniform(
            stealth_state["delay_min"],
            stealth_state["delay_max"]
        )
        await asyncio.sleep(delay)


def create_stealth_connector():
    """
    ステルスモードに応じた aiohttp コネクターを生成する。
    ステルス有効時: SOCKS5プロキシ付きコネクター
    ステルス無効時: 通常のTCPコネクター
    """
    import aiohttp

    if stealth_state["enabled"] and stealth_state["proxy_url"]:
        try:
            from aiohttp_socks import ProxyConnector
            connector = ProxyConnector.from_url(
                stealth_state["proxy_url"],
                limit=100,
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
                force_close=True,
                rdns=True,  # DNS解決もプロキシ側で実施（DNSリーク防止）
            )
            stealth_state["proxy_connected"] = True
            return connector
        except ImportError:
            print("[ステルス] aiohttp-socks がインストールされていません。通常接続にフォールバックします。")
            stealth_state["proxy_connected"] = False
        except Exception as e:
            print(f"[ステルス] プロキシコネクター作成エラー: {e}")
            stealth_state["proxy_connected"] = False

    # 通常のコネクター
    stealth_state["proxy_connected"] = False
    return aiohttp.TCPConnector(
        limit=200,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
        force_close=True,
    )


async def create_proxy_tcp_connection(ip: str, port: int, timeout: int = 3):
    """
    ステルスモード時にプロキシ経由でTCP接続を確立する。
    RTSP/DVRバナー取得などの非HTTP通信で使用。

    Returns:
        (reader, writer) タプル、または接続失敗時はNone
    """
    if stealth_state["enabled"] and stealth_state["proxy_url"]:
        try:
            from python_socks.async_.asyncio import Proxy
            proxy_url = stealth_state["proxy_url"]

            # SOCKS5プロキシ経由で接続
            proxy = Proxy.from_url(proxy_url, rdns=True)
            sock = await asyncio.wait_for(
                proxy.connect(dest_host=ip, dest_port=port),
                timeout=timeout
            )

            # ソケットをasyncioのストリームに変換
            reader, writer = await asyncio.open_connection(
                sock=sock._socket
            )
            return reader, writer

        except ImportError:
            print("[ステルス] python-socks がインストールされていません。直接接続にフォールバックします。")
        except Exception:
            return None

    # 通常の直接接続
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        return reader, writer
    except Exception:
        return None


def get_playwright_proxy_config() -> Optional[dict]:
    """
    Playwright用のプロキシ設定辞書を返す。
    ステルスモード無効時はNoneを返す。
    """
    if stealth_state["enabled"] and stealth_state["proxy_url"]:
        proxy_url = stealth_state["proxy_url"]
        # Playwrightはsocks5://形式に対応している
        return {"server": proxy_url}
    return None


def update_stealth_config(config: dict):
    """ステルスモードの設定を更新する"""
    if "enabled" in config:
        stealth_state["enabled"] = bool(config["enabled"])
    if "proxy_url" in config:
        stealth_state["proxy_url"] = config["proxy_url"].strip()
    if "delay_min" in config:
        stealth_state["delay_min"] = max(0.0, min(10.0, float(config["delay_min"])))
    if "delay_max" in config:
        stealth_state["delay_max"] = max(0.1, min(30.0, float(config["delay_max"])))
    if "randomize_ua" in config:
        stealth_state["randomize_ua"] = bool(config["randomize_ua"])

    # 最小値が最大値を超えないように補正
    if stealth_state["delay_min"] > stealth_state["delay_max"]:
        stealth_state["delay_min"] = stealth_state["delay_max"]

    # ステルス無効時はプロキシ接続状態をリセット
    if not stealth_state["enabled"]:
        stealth_state["proxy_connected"] = False


def get_stealth_status() -> dict:
    """現在のステルス設定と状態を返す"""
    return {
        "enabled": stealth_state["enabled"],
        "proxy_url": stealth_state["proxy_url"],
        "delay_min": stealth_state["delay_min"],
        "delay_max": stealth_state["delay_max"],
        "randomize_ua": stealth_state["randomize_ua"],
        "proxy_connected": stealth_state["proxy_connected"],
        # モニター用追加情報
        "current_ua": get_random_ua(),
        "dns_protection": stealth_state["enabled"] and stealth_state["proxy_connected"],
    }


# ========== ステルス実効性検証 ==========

# 検証結果キャッシュ（30秒間有効）
_verify_cache = {
    "result": None,
    "timestamp": 0,
    "ttl": 30,
}


async def verify_stealth_connection() -> dict:
    """
    ステルスモードの実効性を検証する。
    プロキシ経由と直接の2経路で外部IPを取得し、比較する。
    結果は30秒間キャッシュされる。
    """
    # キャッシュが有効ならそちらを返す
    now = _time.time()
    if _verify_cache["result"] and (now - _verify_cache["timestamp"]) < _verify_cache["ttl"]:
        return _verify_cache["result"]

    result = {
        "proxy_reachable": False,
        "exit_ip": None,
        "direct_ip": None,
        "ip_hidden": False,
        "dns_protected": False,
        "current_ua": get_random_ua(),
        "delay_range": f"{stealth_state['delay_min']:.1f}s 〜 {stealth_state['delay_max']:.1f}s",
        "error": None,
        "checked_at": None,
    }

    import aiohttp
    from datetime import datetime
    result["checked_at"] = datetime.now().isoformat()

    # ステルスモードが無効の場合
    if not stealth_state["enabled"]:
        result["error"] = "ステルスモードが無効です"
        _verify_cache["result"] = result
        _verify_cache["timestamp"] = now
        return result

    # 1. 直接接続で自分のIPを取得
    try:
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=5, force_close=True)
        ) as session:
            async with session.get(
                "https://api.ipify.org?format=json",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["direct_ip"] = data.get("ip")
    except Exception:
        result["direct_ip"] = "取得失敗"

    # 2. プロキシ経由で出口IPを取得
    try:
        connector = create_stealth_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            req_headers = get_random_headers()
            async with session.get(
                "https://api.ipify.org?format=json",
                timeout=aiohttp.ClientTimeout(total=15),
                headers=req_headers,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result["exit_ip"] = data.get("ip")
                    result["proxy_reachable"] = True
    except Exception as e:
        result["exit_ip"] = None
        result["proxy_reachable"] = False
        result["error"] = f"プロキシ接続失敗: {type(e).__name__}"

    # 3. IP秘匿の判定（直接IPと出口IPが異なれば秘匿成功）
    if result["exit_ip"] and result["direct_ip"] and result["direct_ip"] != "取得失敗":
        result["ip_hidden"] = result["exit_ip"] != result["direct_ip"]
    elif result["exit_ip"] and result["proxy_reachable"]:
        # 直接IPが取得できなくても、プロキシ経由で出口IPが取れていれば一応OK
        result["ip_hidden"] = True

    # 4. DNS保護ステータス（rdns=Trueでプロキシ接続済みなら有効）
    result["dns_protected"] = stealth_state["proxy_connected"] and result["proxy_reachable"]

    # キャッシュに保存
    _verify_cache["result"] = result
    _verify_cache["timestamp"] = now

    return result
