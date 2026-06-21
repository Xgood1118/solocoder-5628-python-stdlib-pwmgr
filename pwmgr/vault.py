"""密码库管理模块"""

import os
import json
import time
import uuid
from typing import Dict, List, Optional, Set
from pathlib import Path

from .crypto import CryptoManager
from .entry import Entry, Category


class Vault:
    """密码库"""

    def __init__(self, vault_path: str):
        self.vault_path = Path(vault_path)
        self.crypto = CryptoManager()
        self.entries: Dict[str, Entry] = {}
        self._last_activity: float = 0
        self.auto_lock_minutes: int = 10
        self.created_at: float = 0
        self.version: str = "1.0"

    @property
    def is_locked(self) -> bool:
        return not self.crypto.is_unlocked

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def exists(self) -> bool:
        """检查密码库文件是否存在"""
        return self.vault_path.exists()

    def create(self, master_password: str) -> bool:
        """创建新的密码库"""
        if self.vault_path.exists():
            raise FileExistsError(f"密码库已存在: {self.vault_path}")

        self.crypto.derive_key(master_password)
        self.entries = {}
        self.created_at = time.time()
        self._update_activity()
        self._save_to_disk()
        return True

    def unlock(self, master_password: str) -> bool:
        """解锁密码库"""
        if not self.vault_path.exists():
            raise FileNotFoundError(f"密码库不存在: {self.vault_path}")

        try:
            with open(self.vault_path, "rb") as f:
                encrypted_data = f.read()

            salt = encrypted_data[:CryptoManager.SALT_LENGTH]
            self.crypto.derive_key(master_password, salt)
            data = self.crypto.decrypt_vault(encrypted_data)

            self.entries = {}
            for entry_data in data.get("entries", []):
                entry = Entry.from_dict(entry_data)
                self.entries[entry.id] = entry

            self.created_at = data.get("created_at", time.time())
            self.version = data.get("version", "1.0")
            self.auto_lock_minutes = data.get("auto_lock_minutes", 10)
            self._update_activity()
            return True
        except ValueError:
            self.crypto.lock()
            return False

    def lock(self):
        """锁定密码库"""
        self.crypto.lock()
        self.entries = {}

    def save(self):
        """保存密码库（使用内存中的密钥）"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")
        self._save_to_disk()

    def _save_to_disk(self):
        """实际保存到磁盘"""
        data = {
            "version": self.version,
            "created_at": self.created_at,
            "auto_lock_minutes": self.auto_lock_minutes,
            "entries": [entry.to_dict() for entry in self.entries.values()],
        }

        encrypted_data = self.crypto.encrypt_vault(data)

        temp_path = self.vault_path.with_suffix(".tmp")
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        with open(temp_path, "wb") as f:
            f.write(encrypted_data)

        temp_path.replace(self.vault_path)
        self._update_activity()

    def add_entry(self, entry: Entry) -> str:
        """添加条目"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        if not entry.id:
            entry.id = str(uuid.uuid4())

        self.entries[entry.id] = entry
        self._update_activity()
        return entry.id

    def get_entry(self, entry_id: str) -> Optional[Entry]:
        """获取条目"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        self._update_activity()
        return self.entries.get(entry_id)

    def get_entry_by_title(self, title: str) -> Optional[Entry]:
        """根据标题获取条目"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        for entry in self.entries.values():
            if entry.title.lower() == title.lower():
                self._update_activity()
                return entry
        return None

    def update_entry(self, entry: Entry) -> bool:
        """更新条目"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        if entry.id not in self.entries:
            return False

        entry.updated_at = time.time()
        self.entries[entry.id] = entry
        self._update_activity()
        return True

    def delete_entry(self, entry_id: str) -> bool:
        """删除条目"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        if entry_id not in self.entries:
            return False

        del self.entries[entry_id]
        self._update_activity()
        return True

    def list_entries(
        self,
        category: Optional[Category] = None,
        tag: Optional[str] = None,
        folder: Optional[str] = None,
    ) -> List[Entry]:
        """列出条目，支持筛选"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        entries = list(self.entries.values())

        if category:
            entries = [e for e in entries if e.category == category]

        if tag:
            entries = [e for e in entries if tag in e.tags]

        if folder:
            entries = [e for e in entries if e.folder == folder]

        entries.sort(key=lambda e: e.title.lower())
        self._update_activity()
        return entries

    def search_entries(self, keyword: str) -> List[Entry]:
        """全文搜索：标题、用户名、URL、备注"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        results = []
        for entry in self.entries.values():
            if entry.search(keyword):
                results.append(entry)

        results.sort(key=lambda e: e.title.lower())
        self._update_activity()
        return results

    def find_duplicate_passwords(self) -> Dict[str, List[Entry]]:
        """查找重复密码"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        password_map: Dict[str, List[Entry]] = {}
        for entry in self.entries.values():
            if entry.password:
                if entry.password not in password_map:
                    password_map[entry.password] = []
                password_map[entry.password].append(entry)

        duplicates = {pwd: entries for pwd, entries in password_map.items() if len(entries) > 1}
        self._update_activity()
        return duplicates

    def get_all_categories(self) -> Set[Category]:
        """获取所有使用中的分类"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        categories = set()
        for entry in self.entries.values():
            categories.add(entry.category)
        return categories

    def get_all_tags(self) -> Set[str]:
        """获取所有标签"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        tags = set()
        for entry in self.entries.values():
            for tag in entry.tags:
                tags.add(tag)
        return tags

    def get_all_folders(self) -> Set[str]:
        """获取所有文件夹"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        folders = set()
        for entry in self.entries.values():
            if entry.folder:
                folders.add(entry.folder)
        return folders

    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """修改主密码，重新加密所有数据"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        if not self.vault_path.exists():
            return False

        try:
            with open(self.vault_path, "rb") as f:
                old_encrypted = f.read()

            old_salt = old_encrypted[:CryptoManager.SALT_LENGTH]

            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.exceptions import InvalidTag

            kdf_old = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=CryptoManager.KEY_LENGTH,
                salt=old_salt,
                iterations=CryptoManager.PBKDF2_ITERATIONS,
            )
            old_key = kdf_old.derive(old_password.encode("utf-8"))

            iv = old_encrypted[CryptoManager.SALT_LENGTH:CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH]
            ciphertext = old_encrypted[CryptoManager.SALT_LENGTH + CryptoManager.IV_LENGTH:]
            aesgcm_old = AESGCM(old_key)
            try:
                plaintext = aesgcm_old.decrypt(iv, ciphertext, None)
            except InvalidTag:
                return False

            new_salt = os.urandom(CryptoManager.SALT_LENGTH)
            kdf_new = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=CryptoManager.KEY_LENGTH,
                salt=new_salt,
                iterations=CryptoManager.PBKDF2_ITERATIONS,
            )
            new_key = kdf_new.derive(new_password.encode("utf-8"))

            new_iv = os.urandom(CryptoManager.IV_LENGTH)
            aesgcm_new = AESGCM(new_key)
            new_ciphertext = aesgcm_new.encrypt(new_iv, plaintext, None)

            new_encrypted = new_salt + new_iv + new_ciphertext

            temp_path = self.vault_path.with_suffix(".tmp")
            with open(temp_path, "wb") as f:
                f.write(new_encrypted)
            temp_path.replace(self.vault_path)

            self.crypto._key = new_key
            self.crypto._salt = new_salt
            self._update_activity()
            return True
        except Exception:
            return False

    def check_auto_lock(self) -> bool:
        """检查是否需要自动锁定"""
        if self.is_locked:
            return False

        if self.auto_lock_minutes <= 0:
            return False

        idle_time = time.time() - self._last_activity
        if idle_time >= self.auto_lock_minutes * 60:
            self.lock()
            return True
        return False

    def reset_activity(self):
        """重置活动时间（手动保持活跃）"""
        self._last_activity = time.time()

    def _update_activity(self):
        """更新活动时间"""
        self._last_activity = time.time()

    def get_statistics(self) -> dict:
        """获取密码库统计信息"""
        if self.is_locked:
            raise RuntimeError("密码库已锁定")

        stats = {
            "total_entries": len(self.entries),
            "by_category": {},
            "total_tags": len(self.get_all_tags()),
            "total_folders": len(self.get_all_folders()),
            "weak_passwords": 0,
            "duplicate_password_groups": 0,
            "duplicate_password_count": 0,
            "totp_enabled": 0,
        }

        for cat in Category:
            stats["by_category"][cat.value] = 0

        from .generator import evaluate_password_strength

        weak_count = 0
        for entry in self.entries.values():
            stats["by_category"][entry.category.value] += 1
            if entry.totp.is_enabled:
                stats["totp_enabled"] += 1
            if entry.password:
                strength = evaluate_password_strength(entry.password)
                if strength.level in ("weak", "very_weak"):
                    weak_count += 1

        stats["weak_passwords"] = weak_count

        duplicates = self.find_duplicate_passwords()
        stats["duplicate_password_groups"] = len(duplicates)
        stats["duplicate_password_count"] = sum(len(v) for v in duplicates.values())

        return stats
