# 故意含有 Command Injection 的測試檔
import os
import subprocess


def run(user_input):
    # 漏洞：拼接使用者輸入進系統指令
    os.system("rm -rf " + user_input)

    # 安全：固定字串、無拼接（不該誤報）
    os.system("ls -la")
