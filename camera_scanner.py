"""
監視カメラ検出モジュール
IPカメラ/監視カメラでよく使われるポート、プロトコル、メーカーシグネチャを利用して
スキャン対象が監視カメラかどうかを判定する。
"""

import asyncio
import re

# ========== 定数 ==========

# 監視カメラでよく使われるポート一覧
CAMERA_PORTS = [
    # --- HTTP/HTTPS 系（カメラ管理画面） ---
    80,     # 標準HTTP（ほぼ全メーカー共通）
    81,     # 代替HTTP（Foscam, 中華系カメラ）
    88,     # 代替HTTP（一部IPカメラ）
    443,    # HTTPS（Hikvision, Dahua等）
    8080,   # 代替HTTP（汎用）
    8443,   # 代替HTTPS

    # --- RTSP（リアルタイムストリーミング） ---
    554,    # RTSP標準ポート（ほぼ全メーカー）
    8554,   # 代替RTSP
    10554,  # Hikvision代替RTSP（キャリアが554をブロック時用）

    # --- メーカー固有ポート ---
    8000,   # Hikvision SDK / ONVIF（iVMS-4200用）
    8899,   # 一部メーカーのONVIF / 管理ポート
    37777,  # Dahua TCP通信ポート
    37778,  # Dahua UDP/データストリーミング
    34567,  # DVR/NVR系（XMeye等の中華系DVR）
    9000,   # 一部IPカメラ管理ポート
    5000,   # Synology系 / 一部IPカメラ

    # --- ストリーミング ---
    1935,   # RTMP（ライブストリーミング）
]

# カメラ判定用のHTTPポート（これらのポートはHTTPでスキャンする）
CAMERA_HTTP_PORTS = {80, 81, 88, 443, 8080, 8443, 8000, 8899, 9000, 5000}

# バナー取得用ポート（HTTPではなくTCPバナーで判定するポート）
CAMERA_BANNER_PORTS = {554, 8554, 10554, 37777, 37778, 34567, 1935}


# ========== カメラメーカーシグネチャ ==========

# タイトル、サーバーヘッダー、HTMLボディに含まれるキーワードをメーカー別に定義
CAMERA_SIGNATURES = [
    # --- Hikvision ---
    {
        "vendor": "Hikvision",
        "patterns": {
            "title": [
                r"hikvision",
                r"hik[\s-]?vision",
                r"DS-\d{4}",          # モデル番号パターン
                r"DNVR",
                r"iVMS",
            ],
            "server": [
                r"hikvision",
                r"DNVRS-Webs",
                r"App-webs",
                r"Hikvision-Webs",
                r"DVRDVS-Webs",
            ],
            "body": [
                r"hikvision",
                r"/doc/page/login\.asp",
                r"webComponents",
                r"isSecureMode",
                r"doc/page/config",
                r"loginPage",
            ],
        },
    },
    # --- Dahua ---
    {
        "vendor": "Dahua",
        "patterns": {
            "title": [
                r"dahua",
                r"DH-\w+",           # モデル番号パターン
                r"NVR\d+",
                r"Web Service",
            ],
            "server": [
                r"dahua",
                r"DH_HTTP",
                r"DHWEB",
            ],
            "body": [
                r"dahua",
                r"/RPC2",
                r"DHVideoWH498",
                r"class=\"login-main\"",
                r"loginEx",
                r"DHCPManager",
            ],
        },
    },
    # --- Axis ---
    {
        "vendor": "Axis",
        "patterns": {
            "title": [
                r"axis",
                r"AXIS\s+\w+",
                r"Live\s?View.*Axis",
            ],
            "server": [
                r"Boa/",
                r"AXIS",
            ],
            "body": [
                r"axis-cgi",
                r"/view/viewer_index\.shtml",
                r"axiscam",
                r"AXIS.*Network Camera",
            ],
        },
    },
    # --- Foscam ---
    {
        "vendor": "Foscam",
        "patterns": {
            "title": [
                r"foscam",
                r"IP\s?Camera",
                r"IPCam",
            ],
            "server": [
                r"foscam",
                r"IPCam",
            ],
            "body": [
                r"foscam",
                r"IPCam_WebLog",
                r"/cgi-bin/CGIProxy\.fcgi",
            ],
        },
    },
    # --- Reolink ---
    {
        "vendor": "Reolink",
        "patterns": {
            "title": [
                r"reolink",
            ],
            "server": [
                r"reolink",
            ],
            "body": [
                r"reolink",
                r"/api\.cgi\?cmd=",
                r"RLC-\d+",          # モデル番号パターン
            ],
        },
    },
    # --- TP-Link ---
    {
        "vendor": "TP-Link",
        "patterns": {
            "title": [
                r"tp-link",
                r"Tapo",
                r"VIGI",
            ],
            "server": [
                r"tp-link",
            ],
            "body": [
                r"tp-link",
                r"Tapo",
                r"VIGI",
            ],
        },
    },
    # --- Vivotek ---
    {
        "vendor": "Vivotek",
        "patterns": {
            "title": [
                r"vivotek",
                r"Network Camera",
            ],
            "server": [
                r"vivotek",
            ],
            "body": [
                r"vivotek",
                r"/cgi-bin/viewer",
                r"VivotekActiveX",
            ],
        },
    },
    # --- Panasonic ---
    {
        "vendor": "Panasonic",
        "patterns": {
            "title": [
                r"panasonic",
                r"WV-\w+",           # モデル番号パターン
                r"Network\s?Camera",
                r"BB-\w+",
            ],
            "server": [
                r"panasonic",
                r"PS-HTTP",
            ],
            "body": [
                r"panasonic",
                r"CgiTagMenu",
                r"/nphMotionJpeg",
            ],
        },
    },
    # --- Samsung / Hanwha ---
    {
        "vendor": "Samsung/Hanwha",
        "patterns": {
            "title": [
                r"samsung",
                r"hanwha",
                r"wisenet",
                r"SNP-\w+",
                r"SNO-\w+",
            ],
            "server": [
                r"samsung",
                r"hanwha",
                r"wisenet",
            ],
            "body": [
                r"samsung",
                r"hanwha",
                r"wisenet",
                r"techwin",
            ],
        },
    },
    # --- Bosch ---
    {
        "vendor": "Bosch",
        "patterns": {
            "title": [
                r"bosch",
                r"VIP\s?\d+",
                r"DINION",
                r"FLEXIDOME",
                r"AutoDome",
            ],
            "server": [
                r"bosch",
            ],
            "body": [
                r"bosch",
                r"DINION",
                r"FLEXIDOME",
                r"/rcp\.xml",
            ],
        },
    },
    # --- 汎用カメラキーワード ---
    {
        "vendor": "Generic Camera",
        "patterns": {
            "title": [
                r"IP\s?Camera",
                r"Web\s?Camera",
                r"Network\s?Camera",
                r"Net\s?Camera",
                r"DVR",
                r"NVR",
                r"Video\s?Server",
                r"surveillance",
                r"CCTV",
                r"Live\s?View",
                r"cam\s?viewer",
                r"mjpg",
                r"NetDVR",
            ],
            "server": [
                r"Camera",
                r"DVR",
                r"NVR",
                r"Cam",
                r"GoAhead",         # 多くのIPカメラで使われる軽量Webサーバー
                r"thttpd",          # 組み込みカメラ用
                r"micro_httpd",     # 組み込みカメラ用
                r"mini_httpd",      # 組み込みカメラ用
            ],
            "body": [
                r"onvif",
                r"snapshot\.cgi",
                r"videostream\.cgi",
                r"mjpeg",
                r"video\.mjpg",
                r"stream\.mjpg",
                r"/cgi-bin/snapshot",
                r"/ISAPI/",
                r"GetSnapshot",
                r"motion/jpeg",
                r"live/ch\d+",
                r"cam_pic\.php",
                r"/snap\.jpg",
                r"av\.htm",
            ],
        },
    },
]


def detect_camera(title: str, server: str, body: str, port: int) -> dict | None:
    """
    HTTP/HTTPSレスポンスの内容から監視カメラかどうかを判定する。

    Args:
        title: ページのタイトル
        server: サーバーヘッダー
        body: HTMLボディ（先頭部分）
        port: ポート番号

    Returns:
        カメラ情報の辞書、またはカメラでない場合はNone
        例: {"vendor": "Hikvision", "confidence": "high", "matched_patterns": [...]}
    """
    if not any([title, server, body]):
        return None

    title = title or ""
    server = server or ""
    body = body or ""

    best_match = None
    best_score = 0

    for sig in CAMERA_SIGNATURES:
        matched_patterns = []
        score = 0

        # タイトルマッチ（重要度: 高）
        for pattern in sig["patterns"].get("title", []):
            if re.search(pattern, title, re.IGNORECASE):
                matched_patterns.append(f"title:{pattern}")
                score += 3

        # サーバーヘッダーマッチ（重要度: 高）
        for pattern in sig["patterns"].get("server", []):
            if re.search(pattern, server, re.IGNORECASE):
                matched_patterns.append(f"server:{pattern}")
                score += 3

        # ボディマッチ（重要度: 中）
        for pattern in sig["patterns"].get("body", []):
            if re.search(pattern, body, re.IGNORECASE):
                matched_patterns.append(f"body:{pattern}")
                score += 2

        # カメラ固有ポート使用時のボーナス
        if port in CAMERA_BANNER_PORTS:
            score += 1

        if score > best_score and matched_patterns:
            best_score = score
            # 信頼度を判定
            if score >= 5:
                confidence = "high"
            elif score >= 3:
                confidence = "medium"
            else:
                confidence = "low"

            best_match = {
                "vendor": sig["vendor"],
                "confidence": confidence,
                "score": score,
                "matched_patterns": matched_patterns,
            }

    return best_match


async def check_rtsp_banner(ip: str, port: int, timeout: int = 3) -> dict | None:
    """
    RTSPポートに接続してバナーを取得し、カメラかどうかを判定する。

    RTSPサーバーはOPTIONSリクエストに応答する。レスポンスからカメラ情報を推測。

    Args:
        ip: 対象IPアドレス
        port: RTSPポート（554, 8554, 10554等）
        timeout: 接続タイムアウト（秒）

    Returns:
        RTSP情報の辞書、またはRTSPサーバーでない場合はNone
        例: {"type": "RTSP", "banner": "RTSP/1.0 ...", "vendor": "Hikvision"}
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )

        # RTSP OPTIONSリクエストを送信
        rtsp_request = (
            f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: IPScanner/2.0\r\n"
            f"\r\n"
        ).encode()

        writer.write(rtsp_request)
        await writer.drain()

        # レスポンスを読み取り
        try:
            response = await asyncio.wait_for(reader.read(2048), timeout=3)
        except asyncio.TimeoutError:
            writer.close()
            await writer.wait_closed()
            return None

        writer.close()
        await writer.wait_closed()

        banner = response.decode("utf-8", errors="ignore").strip()

        # RTSPレスポンスかどうか確認
        if not banner.startswith("RTSP/"):
            return None

        result = {
            "type": "RTSP",
            "banner": banner[:500],
            "vendor": None,
        }

        # バナーからメーカーを推測
        banner_lower = banner.lower()
        if "hikvision" in banner_lower or "hikvis" in banner_lower:
            result["vendor"] = "Hikvision"
        elif "dahua" in banner_lower:
            result["vendor"] = "Dahua"
        elif "axis" in banner_lower:
            result["vendor"] = "Axis"
        elif "reolink" in banner_lower:
            result["vendor"] = "Reolink"
        elif "foscam" in banner_lower:
            result["vendor"] = "Foscam"
        elif "vivotek" in banner_lower:
            result["vendor"] = "Vivotek"
        elif "panasonic" in banner_lower:
            result["vendor"] = "Panasonic"
        elif "bosch" in banner_lower:
            result["vendor"] = "Bosch"
        elif "samsung" in banner_lower or "hanwha" in banner_lower:
            result["vendor"] = "Samsung/Hanwha"
        elif "tp-link" in banner_lower or "tapo" in banner_lower:
            result["vendor"] = "TP-Link"

        return result

    except Exception:
        return None


async def check_dvr_banner(ip: str, port: int, timeout: int = 3) -> dict | None:
    """
    DVR/NVR系ポート（37777, 34567等）に接続してバナーを取得する。

    Args:
        ip: 対象IPアドレス
        port: DVR/NVRポート
        timeout: 接続タイムアウト（秒）

    Returns:
        DVR/NVR情報の辞書、またはサービスが見つからない場合はNone
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )

        # バナーを取得（DVR系は接続するとバナーを返すことが多い）
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
        except asyncio.TimeoutError:
            # タイムアウトしても接続できた＝ポートは空いている
            writer.close()
            await writer.wait_closed()
            return {
                "type": "DVR/NVR",
                "banner": "(接続成功・バナーなし)",
                "vendor": _guess_vendor_from_port(port),
            }

        writer.close()
        await writer.wait_closed()

        banner_text = banner.decode("utf-8", errors="ignore").strip()

        # メーカー推測
        vendor = _guess_vendor_from_port(port)
        banner_lower = banner_text.lower()
        if "dahua" in banner_lower:
            vendor = "Dahua"
        elif "hikvision" in banner_lower or "hikvis" in banner_lower:
            vendor = "Hikvision"

        return {
            "type": "DVR/NVR",
            "banner": banner_text[:500] if banner_text else "(バナーなし)",
            "vendor": vendor,
        }

    except Exception:
        return None


def _guess_vendor_from_port(port: int) -> str | None:
    """ポート番号からメーカーを推測する"""
    vendor_ports = {
        37777: "Dahua",
        37778: "Dahua",
        8000: "Hikvision",
        10554: "Hikvision",
        34567: "XMeye/Generic DVR",
    }
    return vendor_ports.get(port)
