# 故意含有 SQL Injection 的測試檔
def get_user(cursor, user_input):
    # 漏洞：字串拼接使用者輸入進 SQL 查詢
    cursor.execute("SELECT * FROM users WHERE id=" + user_input)

    # 安全：參數化查詢（不該誤報）
    cursor.execute("SELECT * FROM users WHERE id=?", (user_input,))
