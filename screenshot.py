"""
スクリーンショット取得モジュール
Playwright（Chromium headless）を使用してWebページのスクリーンショットを撮影する。
"""

import os
import asyncio
from datetime import datetime

# スクリーンショット保存ディレクトリ
SCREENSHOT_DIR = os.path.join(os.path.dirname(__file__), "screenshots")


async def init_screenshot_dir():
    """スクリーンショット保存ディレクトリを作成する"""
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)


async def take_screenshot(url: str, ip: str, port: int) -> str | None:
    """
    指定URLのスクリーンショットを撮影する。
    戻り値はファイルパス（成功時）またはNone（失敗時）。
    """
    try:
        from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

        # ファイル名を生成（IP_ポート_タイムスタンプ.webp）
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{ip.replace('.', '_')}_{port}_{timestamp}.png"
        filepath = os.path.join(SCREENSHOT_DIR, filename)

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--ignore-certificate-errors",  # 自己署名証明書も許可
                ]
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720},
                ignore_https_errors=True,  # SSL エラーを無視
            )
            page = await context.new_page()

            try:
                # ページを読み込む（最大15秒）
                try:
                    await page.goto(url, timeout=15000, wait_until="load")
                except PlaywrightTimeoutError:
                    print(f"Timeout on {url}, taking screenshot anyway", flush=True)
                except Exception as e:
                    print(f"Goto error on {url}: {e}", flush=True)
                    
                # 少し待ってレンダリング完了を待つ
                await asyncio.sleep(2)
                # スクリーンショットを撮影
                await page.screenshot(path=filepath, type="png")
                return filename
            except Exception as e:
                print(f"Screenshot error for {url}: {e}", flush=True)
                return None
            finally:
                await browser.close()

    except ImportError as e:
        print(f"Playwright ImportError: {e}", flush=True)
        return None
    except Exception as e:
        print(f"Screenshot top-level error: {e}", flush=True)
        return None
