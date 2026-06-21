"""密码条目数据模型"""

import uuid
import time
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class Category(Enum):
    """默认分类"""
    LOGIN = "login"
    CREDIT_CARD = "credit_card"
    SECURE_NOTE = "secure_note"
    SSH_KEY = "ssh_key"
    WIFI = "wifi"
    SOFTWARE_LICENSE = "software_license"
    OTHER = "other"

    @classmethod
    def from_str(cls, s: str) -> "Category":
        for cat in cls:
            if cat.value == s or cat.name.lower() == s.lower():
                return cat
        return cls.OTHER

    @classmethod
    def display_name(cls, cat: "Category") -> str:
        names = {
            cls.LOGIN: "登录",
            cls.CREDIT_CARD: "信用卡",
            cls.SECURE_NOTE: "安全笔记",
            cls.SSH_KEY: "SSH 密钥",
            cls.WIFI: "WiFi 密码",
            cls.SOFTWARE_LICENSE: "软件许可证",
            cls.OTHER: "其他",
        }
        return names.get(cat, "其他")


@dataclass
class CustomField:
    """自定义字段"""
    name: str
    value: str
    type: str = "text"  # text, password, url, email

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "value": self.value,
            "type": self.type,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CustomField":
        return cls(
            name=d.get("name", ""),
            value=d.get("value", ""),
            type=d.get("type", "text"),
        )


@dataclass
class TOTPConfig:
    """TOTP 配置"""
    secret: str = ""  # base32 编码的密钥
    issuer: str = ""
    digits: int = 6
    period: int = 30
    recovery_codes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "secret": self.secret,
            "issuer": self.issuer,
            "digits": self.digits,
            "period": self.period,
            "recovery_codes": self.recovery_codes.copy(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TOTPConfig":
        return cls(
            secret=d.get("secret", ""),
            issuer=d.get("issuer", ""),
            digits=d.get("digits", 6),
            period=d.get("period", 30),
            recovery_codes=d.get("recovery_codes", []).copy(),
        )

    @property
    def is_enabled(self) -> bool:
        return bool(self.secret)


@dataclass
class PasswordHistoryEntry:
    """密码历史条目"""
    password: str
    timestamp: float

    def to_dict(self) -> dict:
        return {
            "password": self.password,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PasswordHistoryEntry":
        return cls(
            password=d.get("password", ""),
            timestamp=d.get("timestamp", 0.0),
        )


@dataclass
class Entry:
    """密码条目"""
    id: str = ""
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    category: Category = Category.LOGIN
    tags: List[str] = field(default_factory=list)
    custom_fields: List[CustomField] = field(default_factory=list)
    folder: str = ""
    totp: TOTPConfig = field(default_factory=TOTPConfig)
    password_history: List[PasswordHistoryEntry] = field(default_factory=list)
    password_history_limit: int = 10
    created_at: float = 0.0
    updated_at: float = 0.0

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        now = time.time()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def update_password(self, new_password: str):
        """更新密码，保存到历史记录"""
        if self.password and self.password != new_password:
            history_entry = PasswordHistoryEntry(
                password=self.password,
                timestamp=time.time()
            )
            self.password_history.insert(0, history_entry)
            if len(self.password_history) > self.password_history_limit:
                self.password_history = self.password_history[:self.password_history_limit]
        self.password = new_password
        self.updated_at = time.time()

    def is_password_reused(self, password: str) -> bool:
        """检查密码是否在历史记录中使用过"""
        if password == self.password:
            return True
        for entry in self.password_history:
            if entry.password == password:
                return True
        return False

    def add_tag(self, tag: str):
        """添加标签"""
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def remove_tag(self, tag: str):
        """移除标签"""
        if tag in self.tags:
            self.tags.remove(tag)

    def add_custom_field(self, name: str, value: str, field_type: str = "text"):
        """添加自定义字段"""
        field = CustomField(name=name, value=value, type=field_type)
        self.custom_fields.append(field)

    def remove_custom_field(self, name: str):
        """移除自定义字段"""
        self.custom_fields = [f for f in self.custom_fields if f.name != name]

    def get_custom_field(self, name: str) -> Optional[CustomField]:
        """获取自定义字段"""
        for f in self.custom_fields:
            if f.name == name:
                return f
        return None

    def search(self, keyword: str) -> bool:
        """全文搜索：标题、用户名、URL、备注"""
        if not keyword:
            return True
        keyword_lower = keyword.lower()
        if keyword_lower in self.title.lower():
            return True
        if keyword_lower in self.username.lower():
            return True
        if keyword_lower in self.url.lower():
            return True
        if keyword_lower in self.notes.lower():
            return True
        for field in self.custom_fields:
            if keyword_lower in field.name.lower() or keyword_lower in field.value.lower():
                return True
        for tag in self.tags:
            if keyword_lower in tag.lower():
                return True
        return False

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "title": self.title,
            "username": self.username,
            "password": self.password,
            "url": self.url,
            "notes": self.notes,
            "category": self.category.value,
            "tags": self.tags.copy(),
            "custom_fields": [f.to_dict() for f in self.custom_fields],
            "folder": self.folder,
            "totp": self.totp.to_dict(),
            "password_history": [h.to_dict() for h in self.password_history],
            "password_history_limit": self.password_history_limit,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        """从字典创建条目"""
        return cls(
            id=d.get("id", ""),
            title=d.get("title", ""),
            username=d.get("username", ""),
            password=d.get("password", ""),
            url=d.get("url", ""),
            notes=d.get("notes", ""),
            category=Category.from_str(d.get("category", "login")),
            tags=d.get("tags", []).copy(),
            custom_fields=[CustomField.from_dict(f) for f in d.get("custom_fields", [])],
            folder=d.get("folder", ""),
            totp=TOTPConfig.from_dict(d.get("totp", {})),
            password_history=[PasswordHistoryEntry.from_dict(h) for h in d.get("password_history", [])],
            password_history_limit=d.get("password_history_limit", 10),
            created_at=d.get("created_at", 0.0),
            updated_at=d.get("updated_at", 0.0),
        )

    def summary(self) -> str:
        """获取条目摘要"""
        return f"[{self.id[:8]}] {self.title} - {self.username}"

    def __repr__(self) -> str:
        return f"Entry(id={self.id[:8]}..., title='{self.title}')"
