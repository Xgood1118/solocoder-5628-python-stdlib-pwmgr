"""数据导入模块 - 支持多种格式"""

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Optional

from .entry import Entry, Category


class ImportResult:
    """导入结果"""

    def __init__(self):
        self.imported: List[Entry] = []
        self.skipped: List[str] = []
        self.errors: List[str] = []
        self.format_detected: str = ""

    @property
    def success_count(self) -> int:
        return len(self.imported)

    @property
    def skip_count(self) -> int:
        return len(self.skipped)

    @property
    def error_count(self) -> int:
        return len(self.errors)


def detect_format(file_path: str) -> str:
    """检测文件格式

    Returns:
        格式名称: 1password, lastpass, chrome, keepass, csv, unknown
    """
    path = Path(file_path)
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return _detect_csv_format(path)
    elif suffix == ".json":
        return _detect_json_format(path)
    elif suffix == ".xml":
        return "keepass"
    return "unknown"


def _detect_csv_format(path: Path) -> str:
    """检测 CSV 格式类型"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader, [])

        header_lower = [h.lower().strip() for h in headers]

        if "url" in header_lower and "username" in header_lower and "password" in header_lower:
            if "notes" in header_lower and "type" in header_lower:
                return "1password"
            if "name" in header_lower:
                return "lastpass"
            if "name" in header_lower or "title" in header_lower:
                return "chrome"

        return "csv"
    except Exception:
        return "csv"


def _detect_json_format(path: Path) -> str:
    """检测 JSON 格式类型"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            if "items" in data and "vault" in data:
                return "1password"
            if "logins" in data:
                return "chrome"

        return "json"
    except Exception:
        return "json"


def import_file(file_path: str, format_type: Optional[str] = None) -> ImportResult:
    """导入密码文件

    Args:
        file_path: 文件路径
        format_type: 格式类型，自动检测为 None

    Returns:
        ImportResult 导入结果
    """
    if format_type is None:
        format_type = detect_format(file_path)

    result = ImportResult()
    result.format_detected = format_type

    try:
        if format_type == "1password":
            result = _import_1password(file_path)
        elif format_type == "lastpass":
            result = _import_lastpass(file_path)
        elif format_type == "chrome":
            result = _import_chrome(file_path)
        elif format_type == "keepass":
            result = _import_keepass(file_path)
        elif format_type == "csv":
            result = _import_generic_csv(file_path)
        elif format_type == "json":
            result = _import_generic_json(file_path)
        else:
            result.errors.append(f"不支持的格式: {format_type}")
    except Exception as e:
        result.errors.append(f"导入失败: {str(e)}")

    return result


def _import_1password(file_path: str) -> ImportResult:
    """导入 1Password CSV 格式"""
    result = ImportResult()
    result.format_detected = "1password"

    path = Path(file_path)
    if path.suffix.lower() == ".csv":
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = Entry(
                        title=row.get("Title", "").strip(),
                        username=row.get("Username", "").strip(),
                        password=row.get("Password", "").strip(),
                        url=row.get("URL", "").strip(),
                        notes=row.get("Notes", "").strip(),
                    )

                    category_str = row.get("Type", "").strip().lower()
                    entry.category = _map_category(category_str)

                    tags_str = row.get("Tags", "").strip()
                    if tags_str:
                        entry.tags = [t.strip() for t in tags_str.split(",") if t.strip()]

                    if entry.title or entry.url:
                        result.imported.append(entry)
                    else:
                        result.skipped.append("缺少标题和URL")
                except Exception as e:
                    result.errors.append(f"行处理失败: {e}")
    else:
        result.errors.append("1Password JSON 格式暂未完全支持，请使用 CSV 格式")

    return result


def _import_lastpass(file_path: str) -> ImportResult:
    """导入 LastPass CSV 格式"""
    result = ImportResult()
    result.format_detected = "lastpass"

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                entry = Entry(
                    title=row.get("name", "").strip(),
                    username=row.get("username", "").strip(),
                    password=row.get("password", "").strip(),
                    url=row.get("url", "").strip(),
                    notes=row.get("extra", "").strip(),
                )

                group = row.get("grouping", "").strip()
                if group:
                    entry.folder = group

                if entry.title or entry.url:
                    result.imported.append(entry)
                else:
                    result.skipped.append("缺少标题和URL")
            except Exception as e:
                result.errors.append(f"行处理失败: {e}")

    return result


def _import_chrome(file_path: str) -> ImportResult:
    """导入 Chrome 密码格式"""
    result = ImportResult()
    result.format_detected = "chrome"

    path = Path(file_path)

    if path.suffix.lower() == ".csv":
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    entry = Entry(
                        title=row.get("name", row.get("site_name", "")).strip(),
                        username=row.get("username", "").strip(),
                        password=row.get("password", "").strip(),
                        url=row.get("url", row.get("site_url", "")).strip(),
                        category=Category.LOGIN,
                    )

                    if entry.title or entry.url:
                        result.imported.append(entry)
                    else:
                        result.skipped.append("缺少标题和URL")
                except Exception as e:
                    result.errors.append(f"行处理失败: {e}")
    elif path.suffix.lower() == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        logins = data.get("logins", [])
        for login in logins:
            try:
                entry = Entry(
                    title=login.get("displayName", "").strip(),
                    username=login.get("userName", "").strip(),
                    password=login.get("password", "").strip(),
                    url=login.get("url", "").strip(),
                    category=Category.LOGIN,
                )

                if entry.title or entry.url:
                    result.imported.append(entry)
                else:
                    result.skipped.append("缺少标题和URL")
            except Exception as e:
                result.errors.append(f"条目处理失败: {e}")

    return result


def _import_keepass(file_path: str) -> ImportResult:
    """导入 KeePass XML 格式"""
    result = ImportResult()
    result.format_detected = "keepass"

    tree = ET.parse(file_path)
    root = tree.getroot()

    entries = root.findall(".//Entry")
    for entry_elem in entries:
        try:
            fields = {}
            for string_elem in entry_elem.findall("String"):
                key = string_elem.find("Key")
                value = string_elem.find("Value")
                if key is not None and value is not None:
                    fields[key.text] = value.text if value.text else ""

            entry = Entry(
                title=fields.get("Title", "").strip(),
                username=fields.get("UserName", "").strip(),
                password=fields.get("Password", "").strip(),
                url=fields.get("URL", "").strip(),
                notes=fields.get("Notes", "").strip(),
            )

            if entry.title or entry.url:
                result.imported.append(entry)
            else:
                result.skipped.append("缺少标题和URL")
        except Exception as e:
            result.errors.append(f"条目处理失败: {e}")

    return result


def _import_generic_csv(file_path: str) -> ImportResult:
    """导入通用 CSV 格式"""
    result = ImportResult()
    result.format_detected = "csv"

    with open(file_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                title = ""
                username = ""
                password = ""
                url = ""
                notes = ""

                for key, value in row.items():
                    key_lower = key.lower().strip()
                    if "title" in key_lower or "name" in key_lower:
                        title = value.strip()
                    elif "user" in key_lower or "login" in key_lower:
                        username = value.strip()
                    elif "pass" in key_lower:
                        password = value.strip()
                    elif "url" in key_lower or "site" in key_lower or "website" in key_lower:
                        url = value.strip()
                    elif "note" in key_lower or "comment" in key_lower or "desc" in key_lower:
                        notes = value.strip()

                entry = Entry(
                    title=title,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes,
                )

                if title or url or username:
                    result.imported.append(entry)
                else:
                    result.skipped.append("无法识别有效字段")
            except Exception as e:
                result.errors.append(f"行处理失败: {e}")

    return result


def _import_generic_json(file_path: str) -> ImportResult:
    """导入通用 JSON 格式"""
    result = ImportResult()
    result.format_detected = "json"

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ["entries", "items", "passwords", "logins"]:
            if key in data and isinstance(data[key], list):
                items = data[key]
                break

    for item in items:
        try:
            if isinstance(item, dict):
                entry = Entry(
                    title=item.get("title", item.get("name", "")).strip(),
                    username=item.get("username", item.get("user", "")).strip(),
                    password=item.get("password", "").strip(),
                    url=item.get("url", item.get("website", "")).strip(),
                    notes=item.get("notes", item.get("description", "")).strip(),
                )

                tags = item.get("tags", [])
                if isinstance(tags, list):
                    entry.tags = [str(t) for t in tags]

                if entry.title or entry.url:
                    result.imported.append(entry)
                else:
                    result.skipped.append("缺少标题和URL")
        except Exception as e:
            result.errors.append(f"条目处理失败: {e}")

    return result


def _map_category(category_str: str) -> Category:
    """映射分类"""
    category_str = category_str.lower().strip()
    mapping = {
        "login": Category.LOGIN,
        "password": Category.LOGIN,
        "credit card": Category.CREDIT_CARD,
        "creditcard": Category.CREDIT_CARD,
        "secure note": Category.SECURE_NOTE,
        "securenote": Category.SECURE_NOTE,
        "note": Category.SECURE_NOTE,
        "ssh key": Category.SSH_KEY,
        "sshkey": Category.SSH_KEY,
        "wifi": Category.WIFI,
        "wireless": Category.WIFI,
        "software license": Category.SOFTWARE_LICENSE,
        "license": Category.SOFTWARE_LICENSE,
    }
    return mapping.get(category_str, Category.LOGIN)
