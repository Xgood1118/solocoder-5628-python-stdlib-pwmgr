"""数据导出模块 - CSV 加密/未加密导出"""

import csv
import json
import os
from pathlib import Path
from typing import List, Optional

from .entry import Entry, Category
from .crypto import CryptoManager


class ExportResult:
    """导出结果"""

    def __init__(self):
        self.exported_count: int = 0
        self.file_path: str = ""
        self.encrypted: bool = False
        self.warnings: List[str] = []

    def to_dict(self) -> dict:
        return {
            "exported_count": self.exported_count,
            "file_path": self.file_path,
            "encrypted": self.encrypted,
            "warnings": self.warnings,
        }


def export_to_csv(
    entries: List[Entry],
    output_path: str,
    encrypted: bool = False,
    password: Optional[str] = None,
    include_history: bool = False,
    include_custom_fields: bool = True,
) -> ExportResult:
    """导出为 CSV 格式

    Args:
        entries: 要导出的条目列表
        output_path: 输出文件路径
        encrypted: 是否加密导出
        password: 加密密码（encrypted=True 时需要）
        include_history: 是否包含密码历史
        include_custom_fields: 是否包含自定义字段

    Returns:
        ExportResult 导出结果
    """
    result = ExportResult()
    result.encrypted = encrypted
    result.file_path = output_path

    if not entries:
        result.warnings.append("没有条目可导出")
        return result

    if not encrypted:
        result.warnings.append("警告: 未加密导出包含明文密码，请妥善保管文件")

    rows = []
    all_fieldnames = set()

    base_fields = [
        "title", "username", "password", "url", "notes",
        "category", "tags", "folder",
    ]
    all_fieldnames.update(base_fields)

    if include_custom_fields:
        all_fieldnames.add("custom_fields")
    if include_history:
        all_fieldnames.add("password_history")

    has_totp = any(entry.totp.is_enabled for entry in entries)
    if has_totp:
        all_fieldnames.update(["totp_secret", "totp_issuer"])

    for entry in entries:
        row = {
            "title": entry.title,
            "username": entry.username,
            "password": entry.password,
            "url": entry.url,
            "notes": entry.notes,
            "category": entry.category.value,
            "tags": ", ".join(entry.tags),
            "folder": entry.folder,
        }

        if include_custom_fields:
            if entry.custom_fields:
                custom_fields_str = "; ".join(
                    f"{f.name}: {f.value}" for f in entry.custom_fields
                )
                row["custom_fields"] = custom_fields_str
            else:
                row["custom_fields"] = ""

        if include_history:
            if entry.password_history:
                history_str = "; ".join(
                    f"[{h.timestamp}] {h.password}" for h in entry.password_history
                )
                row["password_history"] = history_str
            else:
                row["password_history"] = ""

        if has_totp:
            if entry.totp.is_enabled:
                row["totp_secret"] = entry.totp.secret
                row["totp_issuer"] = entry.totp.issuer
            else:
                row["totp_secret"] = ""
                row["totp_issuer"] = ""

        rows.append(row)

    fieldnames = sorted(all_fieldnames)

    if encrypted:
        if not password:
            raise ValueError("加密导出需要提供密码")

        csv_content = _build_csv_string(rows, fieldnames)

        crypto = CryptoManager()
        crypto.derive_key(password)
        encrypted_data = crypto.encrypt_vault({
            "type": "export",
            "format": "csv",
            "data": csv_content,
        })

        with open(output_path, "wb") as f:
            f.write(encrypted_data)
    else:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    result.exported_count = len(entries)
    return result


def export_to_json(
    entries: List[Entry],
    output_path: str,
    encrypted: bool = False,
    password: Optional[str] = None,
) -> ExportResult:
    """导出为 JSON 格式"""
    result = ExportResult()
    result.encrypted = encrypted
    result.file_path = output_path

    if not entries:
        result.warnings.append("没有条目可导出")
        return result

    if not encrypted:
        result.warnings.append("警告: 未加密导出包含明文密码，请妥善保管文件")

    data = {
        "type": "export",
        "format": "json",
        "version": "1.0",
        "count": len(entries),
        "entries": [entry.to_dict() for entry in entries],
    }

    if encrypted:
        if not password:
            raise ValueError("加密导出需要提供密码")

        crypto = CryptoManager()
        crypto.derive_key(password)
        encrypted_data = crypto.encrypt_vault(data)

        with open(output_path, "wb") as f:
            f.write(encrypted_data)
    else:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    result.exported_count = len(entries)
    return result


def _build_csv_string(rows: List[dict], fieldnames: List[str]) -> str:
    """构建 CSV 字符串"""
    import io

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def export_statistics(stats: dict, output_path: str) -> bool:
    """导出统计信息为 JSON"""
    try:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


def get_export_formats() -> List[str]:
    """获取支持的导出格式"""
    return ["csv", "json"]
