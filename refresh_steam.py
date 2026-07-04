"""
整合脚本：刷新 Steam cookie 并加密保存
由 GitHub Action 定时调用
"""

import requests
import os
import sys
import json
import base64
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
    """第二步: 用刷新后的 JWT 获取 steamLoginSecure"""
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
    set_cookie = response.headers.get("Set-Cookie")
    if set_cookie:
        return set_cookie.split("steamLoginSecure=")[1].split("; Expires")[0]
    raise Exception("未获取到 steamLoginSecure")


def encrypt_cookie(cookie_value: str, key: str) -> str:
    """AES-256-GCM 加密"""
    import hashlib
    key_bytes = hashlib.sha256(key.encode()).digest()
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, cookie_value.encode("utf-8"), b"steam-cookie-v1")
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def main():
    # 关闭 SSL 警告（与原始脚本一致）
    requests.packages.urllib3.disable_warnings()

    print(f"[{datetime.now()}] 开始刷新 Steam cookie...")

    # Step 1 & 2: 刷新并获取新 cookie
    result = post_ajaxrefresh()
    print(f"ajaxrefresh 返回: steamID={result.get('steamID', 'N/A')}")

    steam_login_secure = post_settoken(result)
    print(f"获取到新 steamLoginSecure (前20字符): {steam_login_secure[:20]}...")

    # Step 3: 加密
    encrypt_key = os.environ["COOKIE_ENCRYPT_KEY"]
    encrypted = encrypt_cookie(steam_login_secure, encrypt_key)

    # Step 4: 写入文件
    output = {
        "encrypted_cookie": encrypted,
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "version": 1,
    }

    output_path = os.path.join(os.path.dirname(__file__), "cookie.enc.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"加密 cookie 已保存到 {output_path}")
    print(f"更新时间: {output['updated_at']}")


if __name__ == "__main__":
    main()
