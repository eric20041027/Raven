// 故意含有 Hardcoded Secret 的 JS 測試檔
const API_KEY = "sk-prod-abc123def456ghi789";   // 漏洞：密鑰寫死

function connect() {
    const dbPassword = "super_secret_pw_123";    // 漏洞
    return dbPassword;
}

const greeting = "hello world";                  // 安全：非密鑰、不該誤報
