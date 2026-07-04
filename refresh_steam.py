"""
整合脚本：刷新 Steam cookie 并加密保存
由 GitHub Action 定时调用

输出格式 (cookie.enc.json):
{
  "encrypted_cookies": {
    "steamLoginSecure": "<base64_encrypted>",
    "sessionid": "<base64_encrypted>"
  },
  "updated_at": "2025-01-01T00:00:00Z",
 "version": 2
}
"""

import requests
import os
import sys
import json
import base64
import re
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def post_ajaxrefresh():
    """第一步: 用长期 cookie 刷新 JWT"""
    url = "https://login.steampowered.com/jwt/ajaxrefresh"
    data = (
        '------WebKitFormBoundaryFpIXysbQReBvAP3T\n'
        'Content-Disposition: form-data; name="redir"\n\n'
        'https://steamcommunity.com\n'
        '------WebKitFormBoundaryFpIXysbQReBvAP3T--'
    )
    cookies = {
        "steamRefresh_steam": os.environ["STEAM_REFRESH_COOKIE"]
    }
    response = requests.post(
        url=url,
        headers={
            "Host": "login.steampowered.com",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryFpIXysbQReBvAP3T",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Origin": "https://steamcommunity.com",
            "Referer": "https://steamcommunity.com/",
        },
        timeout=8,
        cookies=cookies,
        data=data,
        verify=False,
    )
    return response.json()


def post_settoken(result_json):
    """第二步: 用刷新后的 JWT 获取 steamLoginSecure 和 sessionid"""
    url = "https://steamcommunity.com/login/settoken"
    steam_id = result_json["steamID"]
    nonce = result_json["nonce"]
    redir = result_json["redir"]
    auth = result_json["auth"]
    data = (
        f'------WebKitFormBoundaryOAaAoQLiUVAH71AI\n'
        f'Content-Disposition: form-data; name="steamID"\n\n{steam_id}\n'
        f'------WebKitFormBoundaryOAaAoQLiUVAH71AI\n'
        f'Content-Disposition: form-data; name="nonce"\n\n{nonce}\n'
        f'------WebKitFormBoundaryOAaAoQLiUVAH71AI\n'
        f'Content-Disposition: form-data; name="redir"\n\n{redir}\n'
        f'------WebKitFormBoundaryOAaAoQLiUVAH71AI\n'
        f'Content-Disposition: form-data; name="auth"\n\n{auth}\n'
        f'------WebKitFormBoundaryOAaAoQLiUVAH71AI--'
    )
    response = requests.post(
        url=url,
        headers={
            "Host": "steamcommunity.com",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryOAaAoQLiUVAH71AI",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Origin": "https://steamcommunity.com",
            "Referer": "https://steamcommunity.com/",
        },
        data=data,
        verify=False,
    )

    # 从 Set-Cookie 头提取 steamLoginSecure 和 sessionid
    set_cookies = response.headers.get("Set-Cookie", "")

    # 也可能在响应体的 cookies 中
    all_cookies = set_cookies
    if response.cookies:
        for key, value in response.cookies.items():
            all_cookies += f"; {key}={value}"

    steam_login_secure = None
    sessionid = None

    # 提取 steamLoginSecure
    match = re.search(r'steamLoginSecure=([^;]+)', all_cookies)
    if match:
        steam_login_secure = match.group(1)

    # 提取 sessionid
    match = re.search(r'sessionid=([^;]+)', all_cookies)
    if match:
        sessionid = match.group(1)

    if not steam_login_secure:
        raise Exception("未获取到 steamLoginSecure")

    # sessionid 可能不在 set-cookie 里，如果获取不到需要额外处理
    return steam_login_secure, sessionid


def get_sessionid(steam_login_secure):
    """第三步: 如果上一步没拿到 sessionid，手动获取"""
    url = "https://steamcommunity.com"
    response = requests.get(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Cookie": f"steamLoginSecure={steam_login_secure}",
        },
        verify=False,
        allow_redirects=True,
    )
    # 从响应 cookies 中提取 sessionid
    for cookie in response.cookies:
        if cookie.name == "sessionid":
            return cookie.value
    return None


def encrypt_value(value: str, key: str) -> str:
    """AES-256-GCM 加密单个值"""
    import hashlib
    key_bytes = hashlib.sha256(key.encode()).digest()
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, value.encode("utf-8"), b"steam-cookie-v2")
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def main():
    # 关闭 SSL 警告（与原始脚本一致）
    requests.packages.urllib3.disable_warnings()

    print(f"[{datetime.now()}] 开始刷新 Steam cookie...")

    # Step 1 & 2: 刷新并获取 cookie
    result = post_ajaxrefresh()
    print(f"ajaxrefresh 返回: steamID={result.get('steamID', 'N/A')}")

    steam_login_secure, sessionid = post_settoken(result)
    print(f"获取到 steamLoginSecure (前20字符): {steam_login_secure[:20]}...")

    # 如果 sessionid 没有拿到，尝试额外请求获取
    if not sessionid:
        print("sessionid 未在 set-cookie 中找到，尝试额外请求...")
        sessionid = get_sessionid(steam_login_secure)
        if sessionid:
            print(f"成功获取 sessionid (前20字符): {sessionid[:20]}...")
        else:
            print("警告: 无法获取 sessionid，将使用空值")

    # Step 3: 加密
    encrypt_key = os.environ["COOKIE_ENCRYPT_KEY"]

    encrypted_login = encrypt_value(steam_login_secure, encrypt_key)
    encrypted_session = encrypt_value(sessionid or "", encrypt_key)

    # Step 4: 写入文件
    output = {
        "encrypted_cookies": {
            "steamLoginSecure": encrypted_login,
            "sessionid": encrypted_session,
        },
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "version": 2,
    }

    output_path = os.path.join(os.path.dirname(__file__), "cookie.enc.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"加密 cookie 已保存到 {output_path}")
    print(f"更新时间: {output['updated_at']}")
    print(f"sessionid 状态: {'已获取' if sessionid else '未获取'}")


if __name__ == "__main__":
    main()
