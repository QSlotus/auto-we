"""
加密 steam cookie 并写入 cookie.enc 文件
由 GitHub Action 调用，密钥来自环境变量 COOKIE_ENCRYPT_KEY
"""

import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_cookie(cookie_value: str) -> str:
    """用 AES-256-GCM 加密 cookie，返回 base64 编码的字符串"""
    key = os.environ["COOKIE_ENCRYPT_KEY"].encode()
    # AES-256 需要 32 字节密钥
    if len(key) != 32:
        # 用 SHA-256 将任意长度密钥派生为 32 字节
        import hashlib
        key = hashlib.sha256(key).digest()

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM 推荐 12 字节 nonce
    plaintext = cookie_value.encode("utf-8")
    # 附加认证数据（AAD），防止密文被用于其他上下文
    aad = b"steam-cookie-v1"

    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 将 nonce + ciphertext 打包，base64 编码
    combined = nonce + ciphertext
    return base64.b64encode(combined).decode("utf-8")


def main():
    # 读取 st.py 获取的 cookie（通过环境变量传入）
    cookie = os.environ.get("STEAM_LOGIN_SECURE", "")
    if not cookie:
        print("错误: 未获取到 STEAM_LOGIN_SECURE")
        exit(1)

    encrypted = encrypt_cookie(cookie)

    output = {
        "encrypted_cookie": encrypted,
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "version": 1,
    }

    output_path = os.path.join(os.path.dirname(__file__), "..", "cookie.enc.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"加密后的 cookie 已写入 {output_path}")
    print(f"更新时间: {output['updated_at']}")


if __name__ == "__main__":
    main()
