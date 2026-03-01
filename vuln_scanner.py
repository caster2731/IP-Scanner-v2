"""
脆弱性スキャナーモジュール
発見したWebサービスに対して各種セキュリティチェックを実行する。
"""

import aiohttp
import asyncio
import re
import json
from datetime import datetime


# ========== セキュリティヘッダーチェック ==========

# チェック対象のセキュリティヘッダー定義
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "name": "HSTS",
        "description": "HTTP Strict Transport Security が未設定。中間者攻撃のリスクあり。",
        "risk": "medium",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "description": "クリックジャッキング対策ヘッダーが未設定。",
        "risk": "medium",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "description": "MIMEスニッフィング対策ヘッダーが未設定。",
        "risk": "low",
    },
    "Content-Security-Policy": {
        "name": "CSP",
        "description": "Content Security Policy が未設定。XSS攻撃のリスクが増大。",
        "risk": "medium",
    },
    "X-XSS-Protection": {
        "name": "X-XSS-Protection",
        "description": "XSS保護ヘッダーが未設定。",
        "risk": "low",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "description": "リファラーポリシーが未設定。情報漏洩のリスク。",
        "risk": "low",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "description": "パーミッションポリシーが未設定。",
        "risk": "low",
    },
}


def check_security_headers(headers: dict) -> list[dict]:
    """レスポンスヘッダーからセキュリティヘッダーの欠落をチェックする"""
    findings = []
    for header_name, info in SECURITY_HEADERS.items():
        if header_name.lower() not in {k.lower() for k in headers.keys()}:
            findings.append({
                "type": "missing_header",
                "name": info["name"],
                "description": info["description"],
                "risk": info["risk"],
            })
    return findings


# ========== 管理パネル・機密ファイル探索 ==========

# 探索対象パス
SENSITIVE_PATHS = [
    # 管理パネル
    {"path": "/admin", "name": "管理パネル", "risk": "high"},
    {"path": "/admin/", "name": "管理パネル", "risk": "high"},
    {"path": "/administrator", "name": "管理パネル", "risk": "high"},
    {"path": "/wp-admin", "name": "WordPress管理画面", "risk": "high"},
    {"path": "/wp-login.php", "name": "WordPressログイン", "risk": "high"},
    {"path": "/phpmyadmin", "name": "phpMyAdmin", "risk": "critical"},
    {"path": "/phpmyadmin/", "name": "phpMyAdmin", "risk": "critical"},
    {"path": "/cpanel", "name": "cPanel", "risk": "high"},
    {"path": "/webmail", "name": "Webメール", "risk": "medium"},
    # 機密ファイル
    {"path": "/.env", "name": "環境変数ファイル", "risk": "critical"},
    {"path": "/.git/config", "name": "Git設定ファイル", "risk": "critical"},
    {"path": "/.git/HEAD", "name": "Git HEADファイル", "risk": "critical"},
    {"path": "/robots.txt", "name": "robots.txt", "risk": "info"},
    {"path": "/sitemap.xml", "name": "サイトマップ", "risk": "info"},
    {"path": "/.htaccess", "name": "Apache設定ファイル", "risk": "high"},
    {"path": "/wp-config.php.bak", "name": "WP設定バックアップ", "risk": "critical"},
    {"path": "/server-status", "name": "Apacheサーバーステータス", "risk": "medium"},
    {"path": "/server-info", "name": "Apacheサーバー情報", "risk": "medium"},
    {"path": "/.DS_Store", "name": "DS_Store", "risk": "low"},
    {"path": "/backup.sql", "name": "SQLバックアップ", "risk": "critical"},
    {"path": "/dump.sql", "name": "SQLダンプ", "risk": "critical"},
    {"path": "/debug", "name": "デバッグページ", "risk": "high"},
    {"path": "/api/swagger", "name": "Swagger UI", "risk": "medium"},
    {"path": "/api/docs", "name": "API ドキュメント", "risk": "medium"},
    {"path": "/elmah.axd", "name": "ELMAH エラーログ", "risk": "high"},
    {"path": "/trace.axd", "name": "ASP.NET トレース", "risk": "high"},
]


async def check_exposed_paths(session: aiohttp.ClientSession, 
                               base_url: str) -> list[dict]:
    """管理パネル・機密ファイルが公開されていないかチェックする"""
    findings = []

    async def check_path(path_info):
        url = f"{base_url}{path_info['path']}"
        try:
            async with session.get(
                url, 
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False,
                ssl=False
            ) as resp:
                # 200が返ってきた場合、そのパスが存在する
                if resp.status == 200:
                    # レスポンスサイズを確認（エラーページでないか）
                    body = await resp.text(errors="ignore")
                    body_len = len(body)
                    # 非常に小さい（カスタム404）や非常に大きい場合も報告
                    if body_len > 0:
                        return {
                            "type": "exposed_path",
                            "name": f"{path_info['name']} ({path_info['path']})",
                            "description": f"パス {path_info['path']} がアクセス可能（{resp.status}）。{body_len}バイトのレスポンス。",
                            "risk": path_info["risk"],
                            "path": path_info["path"],
                            "status": resp.status,
                        }
                # 403も場合によっては存在の証拠
                elif resp.status == 403:
                    return {
                        "type": "exposed_path",
                        "name": f"{path_info['name']} ({path_info['path']})",
                        "description": f"パス {path_info['path']} が存在するがアクセス拒否（403）。",
                        "risk": "low",
                        "path": path_info["path"],
                        "status": resp.status,
                    }
        except Exception:
            pass
        return None

    # 並行チェック（同時5つまで）
    semaphore = asyncio.Semaphore(5)

    async def limited_check(path_info):
        async with semaphore:
            return await check_path(path_info)

    results = await asyncio.gather(
        *[limited_check(p) for p in SENSITIVE_PATHS],
        return_exceptions=True
    )

    for result in results:
        if isinstance(result, dict) and result is not None:
            findings.append(result)

    return findings


# ========== ディレクトリリスティングチェック ==========

DIRECTORY_LISTING_PATTERNS = [
    r"Index of /",
    r"Directory listing for",
    r"<title>Index of",
    r"Parent Directory",
    r"\[To Parent Directory\]",
]


def check_directory_listing(body: str) -> list[dict]:
    """レスポンスボディにディレクトリリスティングが含まれるかチェックする"""
    findings = []
    for pattern in DIRECTORY_LISTING_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({
                "type": "directory_listing",
                "name": "ディレクトリリスティング",
                "description": "ディレクトリの一覧表示が有効。内部ファイル構造が露出。",
                "risk": "medium",
            })
            break  # 1つ見つかればOK
    return findings


# ========== 技術・バージョン検出 ==========

TECH_PATTERNS = [
    # サーバーからのバージョン情報
    {"header": "Server", "pattern": r"Apache/(\d[\d.]*)", "name": "Apache", "risk": "low"},
    {"header": "Server", "pattern": r"nginx/(\d[\d.]*)", "name": "Nginx", "risk": "low"},
    {"header": "Server", "pattern": r"Microsoft-IIS/(\d[\d.]*)", "name": "IIS", "risk": "low"},
    {"header": "X-Powered-By", "pattern": r"PHP/(\d[\d.]*)", "name": "PHP", "risk": "medium"},
    {"header": "X-Powered-By", "pattern": r"ASP\.NET", "name": "ASP.NET", "risk": "low"},
    {"header": "X-Powered-By", "pattern": r"Express", "name": "Express.js", "risk": "low"},
    {"header": "X-Powered-By", "pattern": r"Next\.js", "name": "Next.js", "risk": "low"},
]

BODY_TECH_PATTERNS = [
    # HTMLボディからの検出
    {"pattern": r"wp-content/", "name": "WordPress", "risk": "low"},
    {"pattern": r"Joomla!", "name": "Joomla", "risk": "low"},
    {"pattern": r"Drupal", "name": "Drupal", "risk": "low"},
    {"pattern": r"<meta name=\"generator\" content=\"([^\"]+)\"", "name": "CMS Generator", "risk": "low"},
]


def check_tech_fingerprint(headers: dict, body: str) -> list[dict]:
    """ヘッダーとボディから技術スタック・バージョン情報を検出する"""
    findings = []
    detected = set()

    # ヘッダーベースの検出
    for tech in TECH_PATTERNS:
        header_val = headers.get(tech["header"], "")
        if header_val:
            match = re.search(tech["pattern"], header_val, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else ""
                name = f"{tech['name']} {version}".strip()
                if name not in detected:
                    detected.add(name)
                    findings.append({
                        "type": "tech_detected",
                        "name": name,
                        "description": f"バージョン情報が露出: {name}。攻撃者に有用な情報。",
                        "risk": tech["risk"],
                    })

    # ボディベースの検出
    if body:
        for tech in BODY_TECH_PATTERNS:
            match = re.search(tech["pattern"], body, re.IGNORECASE)
            if match:
                extra = match.group(1) if match.lastindex else ""
                name = f"{tech['name']} {extra}".strip() if extra else tech["name"]
                if name not in detected:
                    detected.add(name)
                    findings.append({
                        "type": "tech_detected",
                        "name": name,
                        "description": f"技術情報を検出: {name}",
                        "risk": tech["risk"],
                    })

    return findings

def extract_tech_stack(findings: list[dict]) -> list[str]:
    """脆弱性スキャン結果からTech Stackのリストを抽出する"""
    techs = []
    for f in findings:
        if f.get("type") == "tech_detected":
            techs.append(f["name"])
    return techs

# ========== SSL/TLS 脆弱性チェック ==========

def check_ssl_issues(ssl_info: dict, protocol: str) -> list[dict]:
    """SSL証明書の問題をチェックする"""
    findings = []

    # HTTPSでない場合
    if protocol == "http":
        findings.append({
            "type": "ssl_issue",
            "name": "HTTP（非暗号化）",
            "description": "HTTPS未使用。通信内容が平文で送受信される。",
            "risk": "medium",
        })
        return findings

    # 証明書情報がある場合
    if ssl_info.get("expiry"):
        try:
            # 有効期限チェック
            expiry_str = ssl_info["expiry"]
            # OpenSSLの日付フォーマットをパース（例: "Jan  1 00:00:00 2025 GMT"）
            for fmt in ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"]:
                try:
                    expiry_date = datetime.strptime(expiry_str, fmt)
                    if expiry_date < datetime.now():
                        findings.append({
                            "type": "ssl_issue",
                            "name": "SSL証明書期限切れ",
                            "description": f"証明書の有効期限が切れています（{expiry_str}）。",
                            "risk": "high",
                        })
                    break
                except ValueError:
                    continue
        except Exception:
            pass

    # 自己署名の可能性（発行者名でヒューリスティック判定）
    issuer = ssl_info.get("issuer", "") or ""
    if issuer and any(kw in issuer.lower() for kw in ["localhost", "self-signed", "test", "example"]):
        findings.append({
            "type": "ssl_issue",
            "name": "自己署名証明書の疑い",
            "description": f"証明書の発行者が '{issuer}' — 自己署名の可能性。",
            "risk": "medium",
        })

    return findings


# ========== 統合スキャン関数 ==========

async def run_vuln_scan(session: aiohttp.ClientSession, 
                        base_url: str, 
                        headers: dict, 
                        body: str,
                        ssl_info: dict,
                        protocol: str) -> list[dict]:
    """
    全脆弱性チェックを統合実行する。
    戻り値はfindingsリスト（各要素にtype, name, description, riskを含む）。
    """
    all_findings = []

    # 1. セキュリティヘッダーチェック
    all_findings.extend(check_security_headers(headers))

    # 2. ディレクトリリスティングチェック
    all_findings.extend(check_directory_listing(body))

    # 3. 技術・バージョン検出
    all_findings.extend(check_tech_fingerprint(headers, body))

    # 4. SSL/TLS チェック
    all_findings.extend(check_ssl_issues(ssl_info, protocol))

    # 5. 管理パネル・機密ファイル探索（ネットワークアクセスあり）
    try:
        exposed = await check_exposed_paths(session, base_url)
        all_findings.extend(exposed)
    except Exception:
        pass

    return all_findings


def summarize_vulns(findings: list[dict]) -> dict:
    """脆弱性結果のサマリーを生成する"""
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        risk = f.get("risk", "info")
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    # 最高リスクレベルを判定
    max_risk = "info"
    for level in ["critical", "high", "medium", "low", "info"]:
        if risk_counts[level] > 0:
            max_risk = level
            break

    return {
        "total": len(findings),
        "risk_counts": risk_counts,
        "max_risk": max_risk,
    }
