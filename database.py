"""
データベース管理モジュール
スキャン結果をSQLiteに保存・取得する。
"""

import aiosqlite
import os
from datetime import datetime

# データベースファイルパス
DB_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DB_DIR, "ipscan.db")


async def init_db():
    """データベースとテーブルを初期化する"""
    os.makedirs(DB_DIR, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'http',
                status_code INTEGER,
                title TEXT,
                server TEXT,
                ssl_issuer TEXT,
                ssl_expiry TEXT,
                ssl_domain TEXT,
                screenshot_path TEXT,
                response_time_ms INTEGER,
                headers TEXT,
                vulnerabilities TEXT,
                vuln_count INTEGER DEFAULT 0,
                vuln_max_risk TEXT DEFAULT 'info',
                hostname TEXT,
                country TEXT,
                country_code TEXT,
                tech_stack TEXT,
                scanned_at TEXT NOT NULL
            )
        """)
        # インデックス作成（検索高速化）
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_scanned_at ON scan_results(scanned_at DESC)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip ON scan_results(ip)
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_risk ON scan_results(vuln_max_risk)
        """)

        # 既存テーブルにカラムがない場合は追加（マイグレーション）
        try:
            await db.execute("ALTER TABLE scan_results ADD COLUMN vulnerabilities TEXT")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE scan_results ADD COLUMN vuln_count INTEGER DEFAULT 0")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE scan_results ADD COLUMN vuln_max_risk TEXT DEFAULT 'info'")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE scan_results ADD COLUMN hostname TEXT")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE scan_results ADD COLUMN country TEXT")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE scan_results ADD COLUMN country_code TEXT")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE scan_results ADD COLUMN tech_stack TEXT")
        except Exception:
            pass

        await db.commit()


async def save_result(result: dict) -> int:
    """スキャン結果を1件保存する"""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO scan_results 
            (ip, port, protocol, status_code, title, server, 
             ssl_issuer, ssl_expiry, ssl_domain, screenshot_path, 
             response_time_ms, headers, vulnerabilities, vuln_count, 
             vuln_max_risk, hostname, country, country_code, tech_stack, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("ip"),
            result.get("port"),
            result.get("protocol", "http"),
            result.get("status_code"),
            result.get("title"),
            result.get("server"),
            result.get("ssl_issuer"),
            result.get("ssl_expiry"),
            result.get("ssl_domain"),
            result.get("screenshot_path"),
            result.get("response_time_ms"),
            result.get("headers"),
            result.get("vulnerabilities"),
            result.get("vuln_count", 0),
            result.get("vuln_max_risk", "info"),
            result.get("hostname"),
            result.get("country"),
            result.get("country_code"),
            result.get("tech_stack"),
            result.get("scanned_at", datetime.now().isoformat()),
        ))
        await db.commit()
        return cursor.lastrowid


async def get_results(limit: int | None = 100, offset: int = 0, 
                      status_filter: str = None, search: str = None,
                      risk_filter: str = None) -> list[dict]:
    """スキャン結果を取得する（ページネーション・フィルター・全件取得対応）"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM scan_results WHERE 1=1"
        params = []

        # ステータスコードフィルター
        if status_filter:
            if status_filter == "2xx":
                query += " AND status_code >= 200 AND status_code < 300"
            elif status_filter == "3xx":
                query += " AND status_code >= 300 AND status_code < 400"
            elif status_filter == "4xx":
                query += " AND status_code >= 400 AND status_code < 500"
            elif status_filter == "5xx":
                query += " AND status_code >= 500 AND status_code < 600"

        # リスクレベルフィルター
        if risk_filter and risk_filter != "all":
            if risk_filter == "has_vuln":
                query += " AND vuln_count > 0"
            else:
                query += " AND vuln_max_risk = ?"
                params.append(risk_filter)

        # テキスト検索（IP、タイトル、サーバー）
        if search:
            query += " AND (ip LIKE ? OR title LIKE ? OR server LIKE ? OR hostname LIKE ? OR country LIKE ?)"
            search_term = f"%{search}%"
            params.extend([search_term, search_term, search_term, search_term, search_term])

        query += " ORDER BY scanned_at DESC"
        
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([limit, offset])

        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]


async def get_stats() -> dict:
    """統計情報を取得する"""
    async with aiosqlite.connect(DB_PATH) as db:
        # 合計スキャン数
        async with db.execute("SELECT COUNT(*) FROM scan_results") as cursor:
            total = (await cursor.fetchone())[0]

        # ステータスコード別集計
        async with db.execute("""
            SELECT 
                SUM(CASE WHEN status_code >= 200 AND status_code < 300 THEN 1 ELSE 0 END) as success,
                SUM(CASE WHEN status_code >= 300 AND status_code < 400 THEN 1 ELSE 0 END) as redirect,
                SUM(CASE WHEN status_code >= 400 AND status_code < 500 THEN 1 ELSE 0 END) as client_error,
                SUM(CASE WHEN status_code >= 500 AND status_code < 600 THEN 1 ELSE 0 END) as server_error
            FROM scan_results
        """) as cursor:
            row = await cursor.fetchone()
            status_counts = {
                "2xx": row[0] or 0,
                "3xx": row[1] or 0,
                "4xx": row[2] or 0,
                "5xx": row[3] or 0,
            }

        # サーバー種類別TOP10
        async with db.execute("""
            SELECT server, COUNT(*) as cnt 
            FROM scan_results 
            WHERE server IS NOT NULL AND server != ''
            GROUP BY server 
            ORDER BY cnt DESC 
            LIMIT 10
        """) as cursor:
            server_stats = [{"name": row[0], "count": row[1]} 
                           async for row in cursor]

        # 平均レスポンスタイム
        async with db.execute("""
            SELECT AVG(response_time_ms) FROM scan_results 
            WHERE response_time_ms IS NOT NULL
        """) as cursor:
            avg_response = (await cursor.fetchone())[0] or 0

        # 脆弱性統計
        async with db.execute("""
            SELECT 
                SUM(CASE WHEN vuln_max_risk = 'critical' THEN 1 ELSE 0 END),
                SUM(CASE WHEN vuln_max_risk = 'high' THEN 1 ELSE 0 END),
                SUM(CASE WHEN vuln_max_risk = 'medium' THEN 1 ELSE 0 END),
                SUM(CASE WHEN vuln_max_risk = 'low' THEN 1 ELSE 0 END),
                SUM(vuln_count)
            FROM scan_results
            WHERE vuln_count > 0
        """) as cursor:
            vrow = await cursor.fetchone()
            vuln_stats = {
                "critical": vrow[0] or 0,
                "high": vrow[1] or 0,
                "medium": vrow[2] or 0,
                "low": vrow[3] or 0,
                "total_findings": vrow[4] or 0,
            }

        return {
            "total_scans": total,
            "status_counts": status_counts,
            "server_stats": server_stats,
            "avg_response_ms": round(avg_response, 1),
            "vuln_stats": vuln_stats,
        }


async def clear_results():
    """全スキャン結果を削除する"""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM scan_results")
        await db.commit()


async def get_result_by_id(result_id: int) -> dict | None:
    """IDでスキャン結果を1件取得する"""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scan_results WHERE id = ?", (result_id,)
        ) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None
