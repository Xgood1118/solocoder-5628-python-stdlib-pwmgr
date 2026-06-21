"""TOTP 双因素认证模块"""

import time
import hmac
import hashlib
import base64
import struct
import secrets
import urllib.parse
from typing import List, Optional


class TOTPGenerator:
    """TOTP 验证码生成器"""

    def __init__(self, secret: str, digits: int = 6, period: int = 30, issuer: str = ""):
        self.secret = secret.upper().replace(" ", "").replace("-", "")
        self.digits = digits
        self.period = period
        self.issuer = issuer

    def _decode_secret(self) -> bytes:
        """将 base32 编码的密钥解码为字节"""
        secret = self.secret
        padding = 8 - len(secret) % 8
        if padding != 8:
            secret += "=" * padding
        try:
            return base64.b32decode(secret)
        except Exception as e:
            raise ValueError(f"无效的 base32 密钥: {e}")

    def _generate_hmac(self, counter: int) -> bytes:
        """生成 HMAC-SHA1 值"""
        key = self._decode_secret()
        counter_bytes = struct.pack(">Q", counter)
        hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1)
        return hmac_hash.digest()

    def _truncate(self, hmac_result: bytes) -> int:
        """动态截断，获取 31 位整数"""
        offset = hmac_result[-1] & 0x0F
        binary = (
            ((hmac_result[offset] & 0x7F) << 24) |
            ((hmac_result[offset + 1] & 0xFF) << 16) |
            ((hmac_result[offset + 2] & 0xFF) << 8) |
            (hmac_result[offset + 3] & 0xFF)
        )
        return binary

    def generate_code(self, timestamp: Optional[float] = None) -> str:
        """生成当前 TOTP 验证码"""
        if timestamp is None:
            timestamp = time.time()

        counter = int(timestamp) // self.period
        hmac_result = self._generate_hmac(counter)
        binary = self._truncate(hmac_result)
        code = binary % (10 ** self.digits)
        return str(code).zfill(self.digits)

    def time_remaining(self, timestamp: Optional[float] = None) -> int:
        """获取当前验证码剩余有效期（秒）"""
        if timestamp is None:
            timestamp = time.time()
        return self.period - int(timestamp) % self.period

    def progress_ratio(self, timestamp: Optional[float] = None) -> float:
        """获取当前周期的进度比例 (0.0 - 1.0)"""
        if timestamp is None:
            timestamp = time.time()
        elapsed = int(timestamp) % self.period
        return elapsed / self.period

    def progress_bar(self, width: int = 30, timestamp: Optional[float] = None) -> str:
        """生成倒计时进度条"""
        ratio = self.progress_ratio(timestamp)
        remaining = self.time_remaining(timestamp)
        filled = int(width * ratio)
        empty = width - filled

        bar = "[" + "█" * filled + "░" * empty + "]"
        return f"{bar} {remaining}s"

    def generate_recovery_codes(self, count: int = 8, length: int = 16) -> List[str]:
        """生成备用恢复码"""
        codes = []
        for _ in range(count):
            code = ""
            for _ in range(length):
                code += secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
            formatted = "-".join([code[i:i+4] for i in range(0, length, 4)])
            codes.append(formatted)
        return codes

    def verify_code(self, code: str, window: int = 1) -> bool:
        """验证验证码

        Args:
            code: 要验证的验证码
            window: 前后窗口数（允许的时间偏移）

        Returns:
            是否验证通过
        """
        code = code.strip().replace(" ", "")
        if len(code) != self.digits:
            return False

        now = time.time()
        counter = int(now) // self.period

        for offset in range(-window, window + 1):
            test_counter = counter + offset
            hmac_result = self._generate_hmac(test_counter)
            binary = self._truncate(hmac_result)
            expected = str(binary % (10 ** self.digits)).zfill(self.digits)
            if expected == code:
                return True
        return False

    def get_uri(self, account_name: str = "") -> str:
        """生成 otpauth:// URI"""
        params = {
            "secret": self.secret,
            "digits": self.digits,
            "period": self.period,
        }
        if self.issuer:
            params["issuer"] = self.issuer

        label = urllib.parse.quote(account_name or "Account")
        if self.issuer:
            label = urllib.parse.quote(self.issuer) + ":" + label

        return f"otpauth://totp/{label}?" + urllib.parse.urlencode(params)

    @staticmethod
    def generate_secret(length: int = 32) -> str:
        """生成随机 base32 编码的密钥"""
        bytes_length = (length * 5) // 8
        random_bytes = secrets.token_bytes(bytes_length)
        return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


def format_code(code: str, separator: str = " ") -> str:
    """格式化验证码，添加分隔符"""
    if len(code) == 6:
        return code[:3] + separator + code[3:]
    elif len(code) == 8:
        return code[:4] + separator + code[4:]
    return code
