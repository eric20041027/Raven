# 故意含有 Hardcoded Secret 的測試檔（給 RAVEN 練習偵測用）
import os

API_KEY = "sk-prod-abc123def456ghi789"   # ← 這行是漏洞：密鑰寫死

def connect():
    db_password = "super_secret_pw_123"  # ← 這行也是漏洞
    return db_password

# 這些不是漏洞，用來測試「不要誤報」：
SAFE_KEY = os.environ["API_KEY"]         # 從環境變數讀，安全
greeting = "hello world"                  # 普通字串，不是密鑰
