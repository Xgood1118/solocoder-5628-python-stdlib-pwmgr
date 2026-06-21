"""集成测试 - 完整流程验证"""

import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pwmgr.vault import Vault
from pwmgr.entry import Entry, Category
from pwmgr.generator import PasswordGenerator, evaluate_password_strength
from pwmgr.totp import TOTPGenerator
from pwmgr.importer import import_file
from pwmgr.exporter import export_to_csv, export_to_json


def test_full_workflow():
    print("=== 完整工作流程集成测试 ===\n")

    tmpdir = tempfile.mkdtemp()
    vault_path = os.path.join(tmpdir, "my_vault.dat")
    master_password = "MySecurePassword123!"

    try:
        print("1. 创建密码库...")
        vault = Vault(vault_path)
        vault.create(master_password)
        assert not vault.is_locked
        print("   ✓ 密码库创建成功")

        print("\n2. 添加多个条目...")
        entries_data = [
            ("Gmail", "user@gmail.com", "gmailpass123", "https://mail.google.com", "邮箱", ["work", "email"]),
            ("GitHub", "developer", "githubpass456", "https://github.com", "代码托管", ["work", "dev"]),
            ("Amazon", "shop@example.com", "amazonpass789", "https://amazon.com", "购物", ["personal"]),
            ("WiFi-Home", "", "wifipassword", "", "家里WiFi", ["wifi"]),
            ("信用卡", "1234-5678-9012-3456", "1234", "", "主信用卡", ["finance"]),
        ]

        for title, username, password, url, notes, tags in entries_data:
            entry = Entry(
                title=title,
                username=username,
                password=password,
                url=url,
                notes=notes,
                tags=tags,
            )
            if "wifi" in tags:
                entry.category = Category.WIFI
            elif "信用卡" in title or "finance" in tags:
                entry.category = Category.CREDIT_CARD
            vault.add_entry(entry)

        vault.save()
        assert vault.entry_count == 5
        print(f"   ✓ 添加了 {vault.entry_count} 个条目")

        print("\n3. 测试搜索功能...")
        results = vault.search_entries("mail")
        assert len(results) >= 1
        print(f"   ✓ 搜索 'mail' 找到 {len(results)} 个结果")

        results = vault.search_entries("123")
        assert len(results) >= 1
        print(f"   ✓ 搜索 '123' 找到 {len(results)} 个结果")

        print("\n4. 测试分类筛选...")
        wifi_entries = vault.list_entries(category=Category.WIFI)
        assert len(wifi_entries) == 1
        print(f"   ✓ WiFi 分类有 {len(wifi_entries)} 个条目")

        print("\n5. 测试标签筛选...")
        work_tagged = vault.list_entries(tag="work")
        assert len(work_tagged) >= 2
        print(f"   ✓ 'work' 标签有 {len(work_tagged)} 个条目")

        print("\n6. 测试密码查重...")
        duplicates = vault.find_duplicate_passwords()
        assert len(duplicates) == 0
        print("   ✓ 没有重复密码")

        entry = Entry(title="重复测试", username="test", password="gmailpass123")
        vault.add_entry(entry)
        duplicates = vault.find_duplicate_passwords()
        assert len(duplicates) >= 1
        print(f"   ✓ 检测到 {len(duplicates)} 组重复密码")
        vault.delete_entry(entry.id)

        print("\n7. 测试密码生成器...")
        gen = PasswordGenerator(length=24, exclude_ambiguous=True)
        new_password = gen.generate()
        strength = evaluate_password_strength(new_password)
        assert strength.score >= 80
        print(f"   ✓ 生成密码: {new_password}")
        print(f"   ✓ 强度评分: {strength.score}/100 ({strength.level})")

        print("\n8. 测试密码历史...")
        gmail_entry = vault.get_entry_by_title("Gmail")
        old_pwd = gmail_entry.password
        gmail_entry.update_password(new_password)
        vault.update_entry(gmail_entry)

        updated = vault.get_entry_by_title("Gmail")
        assert updated.password == new_password
        assert updated.is_password_reused(old_pwd)
        assert len(updated.password_history) == 1
        print("   ✓ 密码历史记录正常")

        print("\n9. 测试 TOTP...")
        secret = TOTPGenerator.generate_secret()
        totp = TOTPGenerator(secret, issuer="TestService")
        code = totp.generate_code()
        assert len(code) == 6
        assert totp.verify_code(code)
        print(f"   ✓ TOTP 验证码: {code[:3]} {code[3:]}")
        print(f"   ✓ 剩余时间: {totp.time_remaining()}s")

        gmail_entry.totp.secret = secret
        gmail_entry.totp.issuer = "Google"
        gmail_entry.totp.recovery_codes = totp.generate_recovery_codes(5)
        vault.update_entry(gmail_entry)
        vault.save()
        print("   ✓ TOTP 配置已保存")

        print("\n10. 测试导出功能...")
        all_entries = vault.list_entries()
        csv_file = os.path.join(tmpdir, "export.csv")
        result = export_to_csv(all_entries, csv_file)
        assert result.exported_count == 5
        assert os.path.exists(csv_file)
        print(f"   ✓ CSV 导出成功: {result.exported_count} 个条目")

        json_file = os.path.join(tmpdir, "export.json")
        result = export_to_json(all_entries, json_file)
        assert result.exported_count == 5
        assert os.path.exists(json_file)
        print(f"   ✓ JSON 导出成功: {result.exported_count} 个条目")

        print("\n11. 测试导入功能...")
        import_result = import_file(csv_file)
        assert import_result.success_count >= 1
        print(f"   ✓ CSV 导入成功: {import_result.success_count} 个条目")
        print(f"   ✓ 检测格式: {import_result.format_detected}")

        print("\n12. 测试锁定/解锁...")
        vault.lock()
        assert vault.is_locked
        print("   ✓ 锁定成功")

        assert vault.unlock(master_password)
        assert not vault.is_locked
        assert vault.entry_count == 5
        print("   ✓ 解锁成功，数据完整")

        print("\n13. 测试修改主密码...")
        new_master_pwd = "NewMasterPassword456!"
        assert vault.change_master_password(master_password, new_master_pwd)
        print("   ✓ 主密码修改成功")

        vault.lock()
        assert vault.unlock(new_master_pwd)
        assert vault.entry_count == 5
        print("   ✓ 新密码解锁成功，数据完整")

        print("\n14. 测试统计信息...")
        stats = vault.get_statistics()
        assert stats["total_entries"] == 5
        assert stats["totp_enabled"] == 1
        print(f"   ✓ 总条目数: {stats['total_entries']}")
        print(f"   ✓ TOTP 启用: {stats['totp_enabled']}")
        print(f"   ✓ 弱密码: {stats['weak_passwords']}")
        print(f"   ✓ 标签总数: {stats['total_tags']}")

        print("\n15. 测试自定义字段...")
        entry = vault.get_entry_by_title("GitHub")
        entry.add_custom_field("API Key", "sk-1234567890", "password")
        entry.add_custom_field("2FA Backup", "backup-code-123", "text")
        vault.update_entry(entry)
        vault.save()

        updated = vault.get_entry_by_title("GitHub")
        assert len(updated.custom_fields) == 2
        assert updated.get_custom_field("API Key").value == "sk-1234567890"
        print("   ✓ 自定义字段正常")

        print("\n" + "=" * 60)
        print("所有集成测试通过！✓")
        print("=" * 60)
        return True

    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n✗ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    success = test_full_workflow()
    sys.exit(0 if success else 1)
