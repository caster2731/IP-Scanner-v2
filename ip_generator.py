"""
IPアドレスジェネレーター
ランダムなグローバルIPv4アドレスを生成する。
プライベートIP、予約済みIP、特殊用途IPは除外。
"""

import random
import ipaddress

# 除外するIPレンジ（RFC 5735 / RFC 6890 等に基づく）
EXCLUDED_NETWORKS = [
    ipaddress.IPv4Network("0.0.0.0/8"),        # 「このネットワーク」
    ipaddress.IPv4Network("10.0.0.0/8"),       # プライベート（クラスA）
    ipaddress.IPv4Network("100.64.0.0/10"),    # キャリアグレードNAT
    ipaddress.IPv4Network("127.0.0.0/8"),      # ループバック
    ipaddress.IPv4Network("169.254.0.0/16"),   # リンクローカル
    ipaddress.IPv4Network("172.16.0.0/12"),    # プライベート（クラスB）
    ipaddress.IPv4Network("192.0.0.0/24"),     # IETF プロトコル割り当て
    ipaddress.IPv4Network("192.0.2.0/24"),     # ドキュメント用（TEST-NET-1）
    ipaddress.IPv4Network("192.88.99.0/24"),   # 6to4 リレーエニーキャスト
    ipaddress.IPv4Network("192.168.0.0/16"),   # プライベート（クラスC）
    ipaddress.IPv4Network("198.18.0.0/15"),    # ベンチマーク用
    ipaddress.IPv4Network("198.51.100.0/24"),  # ドキュメント用（TEST-NET-2）
    ipaddress.IPv4Network("203.0.113.0/24"),   # ドキュメント用（TEST-NET-3）
    ipaddress.IPv4Network("224.0.0.0/4"),      # マルチキャスト
    ipaddress.IPv4Network("240.0.0.0/4"),      # 将来使用予約
    ipaddress.IPv4Network("255.255.255.255/32"), # ブロードキャスト
]


def is_valid_global_ip(ip: ipaddress.IPv4Address) -> bool:
    """指定されたIPがグローバルIPかどうか判定する"""
    for network in EXCLUDED_NETWORKS:
        if ip in network:
            return False
    return True


def generate_random_ip() -> str:
    """ランダムなグローバルIPv4アドレスを1つ生成する"""
    while True:
        # ランダムな32ビット整数からIPアドレスを生成
        random_int = random.randint(1, 0xFFFFFFFE)
        ip = ipaddress.IPv4Address(random_int)
        if is_valid_global_ip(ip):
            return str(ip)


def generate_random_ips(count: int) -> list[str]:
    """指定した数だけランダムなグローバルIPv4アドレスを生成する"""
    ips = []
    for _ in range(count):
        ips.append(generate_random_ip())
    return ips
