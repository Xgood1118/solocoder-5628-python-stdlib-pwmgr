"""加密核心模块 - AES-GCM + PBKDF2"""

import os
import base64
import json
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


class CryptoManager:
    """加密管理器，负责密钥派生和数据加解密"""

    PBKDF2_ITERATIONS = 100000
    SALT_LENGTH = 32
    IV_LENGTH = 12
    KEY_LENGTH = 32

    def __init__(self):
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def derive_key(self, master_password: str, salt: Optional[bytes] = None) -> bytes:
        """使用 PBKDF2 从主密码派生密钥"""
        if salt is None:
            salt = os.urandom(self.SALT_LENGTH)
        self._salt = salt

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        self._key = kdf.derive(master_password.encode("utf-8"))
        return self._key

    def verify_key(self, master_password: str, salt: bytes) -> bool:
        """验证主密码是否正确"""
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.KEY_LENGTH,
                salt=salt,
                iterations=self.PBKDF2_ITERATIONS,
            )
            kdf.verify(master_password.encode("utf-8"), self._key)
            return True
        except Exception:
            return False

    def rekey(self, old_password: str, new_password: str, encrypted_data: bytes) -> Tuple[bytes, bytes]:
        """更换主密码，使用新密码重新加密数据

        Returns:
            (new_salt, new_encrypted_data)
        """
        salt, iv, ciphertext = self._parse_encrypted(encrypted_data)

        old_key = self._derive_temp_key(old_password, salt)
        aesgcm_old = AESGCM(old_key)
        plaintext = aesgcm_old.decrypt(iv, ciphertext, None)

        new_salt = os.urandom(self.SALT_LENGTH)
        new_key = self._derive_temp_key(new_password, new_salt)
        aesgcm_new = AESGCM(new_key)
        new_iv = os.urandom(self.IV_LENGTH)
        new_ciphertext = aesgcm_new.encrypt(new_iv, plaintext, None)

        self._key = new_key
        self._salt = new_salt

        return new_salt, new_iv + new_ciphertext

    def encrypt(self, plaintext: bytes, iv: Optional[bytes] = None) -> bytes:
        """使用 AES-GCM 加密数据

        每个条目使用独立 IV
        """
        if self._key is None:
            raise RuntimeError("Vault is locked")

        if iv is None:
            iv = os.urandom(self.IV_LENGTH)

        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(iv, plaintext, None)
        return iv + ciphertext

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """解密数据"""
        if self._key is None:
            raise RuntimeError("Vault is locked")

        iv = encrypted_data[:self.IV_LENGTH]
        ciphertext = encrypted_data[self.IV_LENGTH:]

        aesgcm = AESGCM(self._key)
        try:
            return aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag:
            raise ValueError("Decryption failed: invalid key or corrupted data")

    def encrypt_json(self, data: dict) -> bytes:
        """加密 JSON 数据"""
        plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
        return self.encrypt(plaintext)

    def decrypt_json(self, encrypted_data: bytes) -> dict:
        """解密 JSON 数据"""
        plaintext = self.decrypt(encrypted_data)
        return json.loads(plaintext.decode("utf-8"))

    def encrypt_string(self, text: str) -> str:
        """加密字符串并返回 base64 编码结果"""
        encrypted = self.encrypt(text.encode("utf-8"))
        return base64.b64encode(encrypted).decode("ascii")

    def decrypt_string(self, encrypted_b64: str) -> str:
        """解密 base64 编码的字符串"""
        encrypted = base64.b64decode(encrypted_b64.encode("ascii"))
        return self.decrypt(encrypted).decode("utf-8")

    def lock(self):
        """锁定，清除密钥"""
        self._key = None
        self._salt = None

    def get_salt(self) -> Optional[bytes]:
        """获取当前 salt"""
        return self._salt

    def set_salt(self, salt: bytes):
        """设置 salt"""
        self._salt = salt

    def _derive_temp_key(self, password: str, salt: bytes) -> bytes:
        """派生临时密钥（不存储）"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt_vault(self, data: dict) -> bytes:
        """使用当前密钥加密整个 vault 数据

        返回格式: salt + iv + ciphertext
        """
        if self._key is None or self._salt is None:
            raise RuntimeError("Vault is locked")

        iv = os.urandom(self.IV_LENGTH)
        aesgcm = AESGCM(self._key)
        plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(iv, plaintext, None)

        return self._salt + iv + ciphertext

    def decrypt_vault(self, encrypted_data: bytes) -> dict:
        """解密 vault 数据（格式: salt + iv + ciphertext）

        注意：必须先用 derive_key 或 set_salt + _key 设置好密钥
        """
        if self._key is None:
            raise RuntimeError("Vault is locked")

        if len(encrypted_data) < self.SALT_LENGTH + self.IV_LENGTH:
            raise ValueError("Invalid vault file format")

        iv = encrypted_data[self.SALT_LENGTH:self.SALT_LENGTH + self.IV_LENGTH]
        ciphertext = encrypted_data[self.SALT_LENGTH + self.IV_LENGTH:]

        aesgcm = AESGCM(self._key)
        try:
            plaintext = aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag:
            raise ValueError("Invalid master password or corrupted vault")

        return json.loads(plaintext.decode("utf-8"))

    def _parse_encrypted(self, encrypted_data: bytes) -> Tuple[bytes, bytes, bytes]:
        """解析加密数据，返回 (salt, iv, ciphertext)

        注意：vault 文件格式是 salt + iv + ciphertext
        """
        if len(encrypted_data) < self.SALT_LENGTH + self.IV_LENGTH:
            raise ValueError("Invalid encrypted data format")
        salt = encrypted_data[:self.SALT_LENGTH]
        iv = encrypted_data[self.SALT_LENGTH:self.SALT_LENGTH + self.IV_LENGTH]
        ciphertext = encrypted_data[self.SALT_LENGTH + self.IV_LENGTH:]
        return salt, iv, ciphertext


def generate_salt() -> bytes:
    """生成随机 salt"""
    return os.urandom(CryptoManager.SALT_LENGTH)


def encrypt_vault_file(data: dict, master_password: str) -> bytes:
    """加密整个 vault 文件

    文件格式: salt(32字节) + iv(12字节) + ciphertext
    """
    salt = generate_salt()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=CryptoManager.KEY_LENGTH,
        salt=salt,
        iterations=CryptoManager.PBKDF2_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))

    iv = os.urandom(CryptoManager.IV_LENGTH)
    aesgcm = AESGCM(key)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    return salt + iv + ciphertext


def decrypt_vault_file(encrypted_data: bytes, master_password: str) -> dict:
    """解密整个 vault 文件"""
    if len(encrypted_data) < CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH:
        raise ValueError("Invalid vault file format")

    salt = encrypted_data[:CryptoManager.SALT_LENGTH]
    iv = encrypted_data[CryptoManager.SALT_LENGTH:CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH]
    ciphertext = encrypted_data[CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=CryptoManager.KEY_LENGTH,
        salt=salt,
        iterations=CryptoManager.PBKDF2_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
    except InvalidTag:
        raise ValueError("Invalid master password or corrupted vault")

    return json.loads(plaintext.decode("utf-8"))
