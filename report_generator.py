"""
PDFレポート生成モジュール
スキャン結果を集計し、HTMLを生成後、Playwrightを用いてPDF形式で保存する。
"""

import os
from datetime import datetime
from collections import Counter
import json
import asyncio

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")

async def init_report_dir():
    os.makedirs(REPORT_DIR, exist_ok=True)

def calculate_score(critical: int, high: int, medium: int) -> str:
    """脆弱性スコアからA~Fの総合評価を算出する"""
    if critical > 0:
        return "F (危険)"
    elif high > 2:
        return "E (警告)"
    elif high > 0:
        return "D (要注意)"
    elif medium > 2:
        return "C (普通)"
    elif medium > 0:
        return "B (良好)"
    return "A (安全)"

def get_advice(score: str) -> str:
    """スコアに応じた改善アドバイスを返す"""
    if "F" in score:
        return "Criticalレベルの脆弱性が検出されています。直ちにパッチ適用や設定見直しを行ってください。"
    elif "E" in score or "D" in score:
        return "Highレベルの脆弱性が存在します。攻撃対象となるリスクが高いため、早期の対応を推奨します。"
    elif "C" in score or "B" in score:
        return "致命的な脆弱性は見当たりませんが、一部設定やマイナーな脆弱性の改善余地があります。"
    return "適切に管理されています。引き続き現在のセキュリティ基準を維持してください。"

def generate_html_report(results: list[dict]) -> str:
    """スキャン結果の配列からHTMLを生成する"""
    total_scanned = len(results)
    
    # リスク集計
    risk_counter = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    vuln_names = []
    
    for r in results:
        # vulnerabilitiesがパースできるかチェック
        if r.get("vulnerabilities"):
            try:
                vulns = json.loads(r["vulnerabilities"])
                for v in vulns:
                    risk = v.get("risk", "info")
                    if risk in risk_counter:
                        risk_counter[risk] += 1
                    vuln_names.append(v.get("name", "Unknown"))
            except Exception:
                pass
                
        # CVEなどがある場合
        if r.get("cve_list"):
            risk_counter["critical"] += len(r["cve_list"].split(","))

    score = calculate_score(risk_counter["critical"], risk_counter["high"], risk_counter["medium"])
    advice = get_advice(score)
    
    top_vulns = Counter(vuln_names).most_common(5)
    
    # 脆弱性TOP5のHTML
    top_vulns_html = ""
    if top_vulns:
        top_vulns_html = "<ul>"
        for name, count in top_vulns:
            top_vulns_html += f"<li>{name} : {count}件</li>"
        top_vulns_html += "</ul>"
    else:
        top_vulns_html = "<p>特筆すべき脆弱性はありませんでした。</p>"

    # サーバーサマリのHTML
    rows_html = ""
    for r in results[:50]:  # 最大50件まで
        ip_port = f"{r['ip']}:{r['port']}"
        risk = r.get('vuln_max_risk', 'info').upper()
        server = str(r.get('server'))[:30] if r.get('server') else "-"
        title = str(r.get('title'))[:30] if r.get('title') else "-"
        rows_html += f"""
        <tr>
            <td>{ip_port}</td>
            <td>{r.get('status_code', '-')}</td>
            <td>{server}</td>
            <td>{title}</td>
            <td class="risk-{r.get('vuln_max_risk', 'info')}">{risk}</td>
        </tr>
        """

    time_str = datetime.now().strftime("%Y年%m月%d日 %H:%M")

    # CSSも含めた完全なHTML
    html = f"""
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <title>IP Scanner 脆弱性診断レポート</title>
        <style>
            body {{ font-family: 'Helvetica Neue', Arial, 'Yu Gothic', sans-serif; color: #333; line-height: 1.6; margin: 0; padding: 40px; background: #fdfdfd; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            h2 {{ color: #2980b9; margin-top: 30px; border-left: 4px solid #2980b9; padding-left: 10px; }}
            .summary-box {{ background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; margin-bottom: 30px; }}
            .score-box {{ text-align: center; border: 2px solid #ccc; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
            .score {{ font-size: 48px; font-weight: bold; color: #e74c3c; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 12px; }}
            th, td {{ border: 1px solid #dee2e6; padding: 8px; text-align: left; }}
            th {{ background-color: #343a40; color: #fff; }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            .risk-critical {{ color: #dc3545; font-weight: bold; }}
            .risk-high {{ color: #fd7e14; font-weight: bold; }}
            .risk-medium {{ color: #ffc107; font-weight: bold; }}
            .risk-low {{ color: #17a2b8; }}
            .footer {{ margin-top: 50px; text-align: center; font-size: 10px; color: #6c757d; border-top: 1px solid #dee2e6; padding-top: 20px; }}
        </style>
    </head>
    <body>
        <h1>IP Scanner 脆弱性診断レポート</h1>
        <p><strong>出力日時:</strong> {time_str}</p>
        
        <div class="score-box">
            <div>総合リスク評価</div>
            <div class="score">{score}</div>
        </div>

        <div class="summary-box">
            <h2>サマリー</h2>
            <p><strong>スキャン対象ホスト数:</strong> {total_scanned} 件</p>
            <p><strong>総脆弱性検出数:</strong> Critical({risk_counter['critical']}), High({risk_counter['high']}), Medium({risk_counter['medium']}), Low({risk_counter['low']})</p>
            <h3>改善へのアドバイス</h3>
            <p>{advice}</p>
        </div>

        <h2>頻出の脆弱性 TOP 5</h2>
        {top_vulns_html}

        <h2>主要な検出ホスト一覧 (最新50件)</h2>
        <table>
            <thead>
                <tr>
                    <th>IP:Port</th>
                    <th>Status</th>
                    <th>サーバー</th>
                    <th>タイトル</th>
                    <th>最大リスク</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <div class="footer">
            Generated by IP Scanner v2 API
        </div>
    </body>
    </html>
    """
    return html

async def generate_pdf_report(results: list[dict]) -> str | None:
    """結果を用いてPDFを生成し、保存したファイルパスを返す"""
    await init_report_dir()
    html_content = generate_html_report(results)
    
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)

    try:
        from playwright.async_api import async_playwright
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ]
            )
            context = await browser.new_context()
            page = await context.new_page()
            
            # HTMLをセットして待機
            await page.set_content(html_content, wait_until="networkidle")
            
            # PDF出力
            await page.pdf(path=filepath, format="A4", print_background=True, margin={"top": "20mm", "bottom": "20mm", "left": "20mm", "right": "20mm"})
            
            await browser.close()
            
            return filepath
    except ImportError:
        print("Playwright is not installed.")
        return None
    except Exception as e:
        print(f"PDF generation error: {e}")
        return None
