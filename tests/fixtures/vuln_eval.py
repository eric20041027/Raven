# 故意含有 Unsafe eval/exec 的測試檔
def process(user_input):
    # 漏洞：對動態內容呼叫 eval，可執行任意程式碼
    result = eval(user_input)

    # 漏洞：exec 同樣危險
    exec(user_input)

    return result
