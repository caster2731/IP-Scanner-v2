"""
IPスキャナー - メインサーバー
FastAPIによるWebサーバー。REST API、WebSocket、静的ファイル配信を提供する。
脆弱性スキャン、指定IPスキャンに対応。
"""

import asyncio
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from database import init_db, get_results, get_stats, clear_results, get_result_by_id
from scanner import (
    scan_state, scan_worker, scan_target_worker, parse_target_ips,
    ws_connections, reset_scan_state
)
from screenshot import init_screenshot_dir, SCREENSHOT_DIR


# ========== ライフサイクル管理 ==========

@asynccontextmanager
async def lifespan(app: FastAPI):
    """アプリケーション起動・終了時の処理"""
    await init_db()
    await init_screenshot_dir()
    print("=" * 50)
    print("  IPスキャナー v2 サーバー起動")
    print("  脆弱性スキャン＋指定IPスキャン対応")
    print("  ダッシュボード: http://localhost:8000")
    print("=" * 50)
    yield
    scan_state["running"] = False


app = FastAPI(title="IPスキャナー v2", lifespan=lifespan)

# 静的ファイル配信
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# スクリーンショットディレクトリも配信
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
app.mount("/screenshots", StaticFiles(directory=SCREENSHOT_DIR), name="screenshots")


# ========== リクエストモデル ==========

class ScanStartRequest(BaseModel):
    """スキャン開始リクエスト"""
    ports: list[int] = [80, 443]
    take_screenshots: bool = True
    run_vuln_check: bool = True


class TargetScanRequest(BaseModel):
    """指定IPスキャンリクエスト"""
    targets: str  # IP入力テキスト（カンマ区切り、CIDR等）
    ports: list[int] = [80, 443]
    take_screenshots: bool = True
    run_vuln_check: bool = True


# ========== ページ配信 ==========

@app.get("/")
async def index():
    """ダッシュボードページを返す"""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ========== REST API ==========

@app.post("/api/scan/start")
async def start_scan(request: ScanStartRequest):
    """ランダムスキャンを開始する"""
    if scan_state["running"]:
        return JSONResponse(
            status_code=400,
            content={"error": "スキャンは既に実行中です"}
        )

    valid_ports = [p for p in request.ports if p in (80, 443, 8080, 8443)]
    if not valid_ports:
        return JSONResponse(
            status_code=400,
            content={"error": "有効なポートを指定してください（80, 443, 8080, 8443）"}
        )

    reset_scan_state()
    scan_state["running"] = True
    scan_state["mode"] = "random"

    import time
    scan_state["start_time"] = time.time()

    asyncio.create_task(scan_worker(
        valid_ports, request.take_screenshots, request.run_vuln_check
    ))

    return {"status": "started", "mode": "random", "ports": valid_ports}


@app.post("/api/scan/target")
async def start_target_scan(request: TargetScanRequest):
    """指定IPスキャンを開始する"""
    if scan_state["running"]:
        return JSONResponse(
            status_code=400,
            content={"error": "スキャンは既に実行中です"}
        )

    # IPリストを生成
    target_ips = parse_target_ips(request.targets)
    if not target_ips:
        return JSONResponse(
            status_code=400,
            content={"error": "有効なIPアドレスが見つかりません。形式: 1.1.1.1 / 1.1.1.1,8.8.8.8 / 192.168.0.0/24"}
        )

    valid_ports = [p for p in request.ports if p in (80, 443, 8080, 8443)]
    if not valid_ports:
        return JSONResponse(
            status_code=400,
            content={"error": "有効なポートを指定してください"}
        )

    # 上限チェック（安全のため）
    total_targets = len(target_ips) * len(valid_ports)
    if total_targets > 100000:
        return JSONResponse(
            status_code=400,
            content={"error": f"ターゲット数が多すぎます（{total_targets}件）。100,000件以下にしてください。"}
        )

    reset_scan_state()
    scan_state["running"] = True
    scan_state["mode"] = "target"

    import time
    scan_state["start_time"] = time.time()

    asyncio.create_task(scan_target_worker(
        target_ips, valid_ports, request.take_screenshots, request.run_vuln_check
    ))

    return {
        "status": "started",
        "mode": "target",
        "ports": valid_ports,
        "target_count": len(target_ips),
        "total_scans": total_targets,
    }


@app.post("/api/scan/stop")
async def stop_scan():
    """スキャンを停止する"""
    if not scan_state["running"]:
        return JSONResponse(
            status_code=400,
            content={"error": "スキャンは実行されていません"}
        )
    scan_state["running"] = False
    return {"status": "stopped"}


@app.get("/api/scan/status")
async def get_scan_status():
    """スキャンの現在の状態を取得する"""
    import time
    elapsed = 0
    if scan_state["start_time"]:
        elapsed = int(time.time() - scan_state["start_time"])
    return {
        "running": scan_state["running"],
        "total_scanned": scan_state["total_scanned"],
        "total_found": scan_state["total_found"],
        "current_rate": scan_state["current_rate"],
        "elapsed_seconds": elapsed,
        "mode": scan_state["mode"],
        "target_total": scan_state["target_total"],
        "target_done": scan_state["target_done"],
    }


@app.get("/api/results")
async def api_get_results(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str = Query(default=None),
    search: str = Query(default=None),
    risk_filter: str = Query(default=None),
):
    """スキャン結果を取得する"""
    results = await get_results(limit, offset, status_filter, search, risk_filter)
    return {"results": results, "count": len(results)}


@app.get("/api/results/{result_id}")
async def api_get_result(result_id: int):
    """指定IDのスキャン結果を取得する"""
    result = await get_result_by_id(result_id)
    if not result:
        return JSONResponse(status_code=404, content={"error": "結果が見つかりません"})
    return result


@app.get("/api/stats")
async def api_get_stats():
    """統計情報を取得する"""
    return await get_stats()


@app.delete("/api/results")
async def api_clear_results():
    """全スキャン結果を削除する"""
    await clear_results()
    return {"status": "cleared"}


# ========== WebSocket ==========

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket接続を管理し、リアルタイムでスキャン結果を配信する"""
    await websocket.accept()
    ws_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in ws_connections:
            ws_connections.remove(websocket)


# ========== 起動 ==========

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
