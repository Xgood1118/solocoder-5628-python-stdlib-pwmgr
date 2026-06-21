"""测试脚本 - 验证密码管理器核心功能"""

import os
import sys
import tempfile
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pwmgr.crypto import CryptoManager, encrypt_vault_file, decrypt_vault_file
from pwmgr.entry import Entry, Category
from pwmgr.generator import PasswordGenerator, evaluate_password_strength
from pwmgr.totp import TOTPGenerator
from pwmgr.vault import Vault
from pwmgr.locker import LockManager
from pwmgr.importer import import_file


def test_crypto():
    print("=== 测试加密模块 ===")
    crypto = CryptoManager()

    password = "testpassword123"
    crypto.derive_key(password)
    assert crypto.is_unlocked, "密钥派生失败"
    print("✓ 密钥派生成功")

    plaintext = "Hello, World! 测试中文"
    encrypted = crypto.encrypt(plaintext.encode("utf-8"))
    decrypted = crypto.decrypt(encrypted).decode("utf-8")
    assert decrypted == plaintext, "加解密不匹配"
    print("✓ 加解密成功")

    test_data = {"name": "测试", "value": 123}
    encrypted_json = crypto.encrypt_json(test_data)
    decrypted_data = crypto.decrypt_json(encrypted_json)
    assert decrypted_data == test_data, "JSON 加解密不匹配"
    print("✓ JSON 加解密成功")

    encrypted_vault = crypto.encrypt_vault(test_data)
    decrypted_vault = crypto.decrypt_vault(encrypted_vault)
    assert decrypted_vault == test_data, "Vault 加解密不匹配"
    print("✓ Vault 加解密成功")

    crypto.lock()
    assert not crypto.is_unlocked, "锁定失败"
    print("✓ 锁定成功")

    print()


def test_entry():
    print("=== 测试条目模型 ===")

    entry = Entry(
        title="测试网站",
        username="testuser",
        password="testpass",
        url="https://test.com",
        notes="测试备注",
        category=Category.LOGIN,
    )
    assert entry.id, "ID 未生成"
    assert entry.title == "测试网站", "标题不匹配"
    print("✓ 条目创建成功")

    entry.add_tag("work")
    entry.add_tag("personal")
    assert "work" in entry.tags, "标签添加失败"
    print("✓ 标签管理成功")

    entry.add_custom_field("API Key", "abc123", "password")
    field = entry.get_custom_field("API Key")
    assert field and field.value == "abc123", "自定义字段添加失败"
    print("✓ 自定义字段成功")

    old_pwd = entry.password
    entry.update_password("newpassword")
    assert entry.password == "newpassword", "密码更新失败"
    assert entry.is_password_reused(old_pwd), "密码历史记录失败"
    print("✓ 密码历史记录成功")

    assert entry.search("测试"), "搜索失败"
    assert entry.search("testuser"), "用户名搜索失败"
    assert not entry.search("不存在"), "搜索误匹配"
    print("✓ 搜索功能成功")

    entry_dict = entry.to_dict()
    entry2 = Entry.from_dict(entry_dict)
    assert entry2.title == entry.title, "序列化/反序列化失败"
    print("✓ 序列化/反序列化成功")

    print()


def test_generator():
    print("=== 测试密码生成器 ===")

    gen = PasswordGenerator(length=20)
    password = gen.generate()
    assert len(password) == 20, "密码长度不匹配"
    print(f"✓ 密码生成成功: {password}")

    strength = evaluate_password_strength(password)
    assert 0 <= strength.score <= 100, "强度评分范围错误"
    print(f"✓ 强度评估: {strength.score}/100 ({strength.level})")

    gen_no_symbols = PasswordGenerator(length=16, use_symbols=False)
    pwd2 = gen_no_symbols.generate()
    assert all(c.isalnum() for c in pwd2), "符号过滤失败"
    print("✓ 字符集过滤成功")

    gen_no_ambiguous = PasswordGenerator(length=16, exclude_ambiguous=True)
    pwd3 = gen_no_ambiguous.generate()
    from pwmgr.generator import AMBIGUOUS_CHARS
    assert not any(c in AMBIGUOUS_CHARS for c in pwd3), "歧义字符排除失败"
    print("✓ 歧义字符排除成功")

    print()


def test_totp():
    print("=== 测试 TOTP ===")

    secret = TOTPGenerator.generate_secret()
    assert secret, "密钥生成失败"
    print(f"✓ 密钥生成: {secret}")

    totp = TOTPGenerator(secret)
    code = totp.generate_code()
    assert len(code) == 6, "验证码长度错误"
    print(f"✓ 验证码生成: {code}")

    remaining = totp.time_remaining()
    assert 0 <= remaining <= 30, "剩余时间错误"
    print(f"✓ 剩余时间: {remaining}s")

    progress = totp.progress_bar()
    assert "[" in progress and "]" in progress, "进度条格式错误"
    print(f"✓ 进度条: {progress}")

    recovery_codes = totp.generate_recovery_codes(count=5)
    assert len(recovery_codes) == 5, "恢复码数量错误"
    print(f"✓ 恢复码生成: {len(recovery_codes)} 个")

    assert totp.verify_code(code), "验证码验证失败"
    print("✓ 验证码验证成功")

    uri = totp.get_uri("test@example.com")
    assert uri.startswith("otpauth://totp/"), "URI 格式错误"
    print(f"✓ URI 生成: {uri[:50]}...")

    print()


def test_vault():
    print("=== 测试密码库 ===")

    tmpdir = tempfile.mkdtemp()
    vault_path = os.path.join(tmpdir, "test_vault.dat")

    vault = Vault(vault_path)
    assert not vault.exists(), "新库不应存在"
    print("✓ 新库检测成功")

    master_pwd = "mypassword123"
    vault.create(master_pwd)
    assert vault.exists(), "创建后库应存在"
    assert not vault.is_locked, "创建后应为解锁状态"
    print("✓ 密码库创建成功")

    entry = Entry(
        title="测试条目",
        username="user1",
        password="pass1",
        url="https://example.com",
    )
    entry_id = vault.add_entry(entry)
    assert entry_id in vault.entries, "条目添加失败"
    print("✓ 条目添加成功")

    vault.save()
    print("✓ 保存成功")

    vault.lock()
    assert vault.is_locked, "锁定失败"
    print("✓ 锁定成功")

    assert vault.unlock(master_pwd), "解锁失败"
    assert not vault.is_locked, "解锁后应为未锁定状态"
    print("✓ 解锁成功")

    assert vault.entry_count == 1, "条目数量错误"
    entry2 = vault.get_entry(entry_id)
    assert entry2 and entry2.title == "测试条目", "获取条目失败"
    print("✓ 条目获取成功")

    results = vault.search_entries("测试")
    assert len(results) == 1, "搜索失败"
    print("✓ 搜索成功")

    stats = vault.get_statistics()
    assert stats["total_entries"] == 1, "统计错误"
    print(f"✓ 统计: {stats['total_entries']} 条目")

    duplicates = vault.find_duplicate_passwords()
    assert isinstance(duplicates, dict), "查重返回类型错误"
    print("✓ 查重功能正常")

    entry2.title = "修改后的标题"
    vault.update_entry(entry2)
    entry3 = vault.get_entry(entry_id)
    assert entry3.title == "修改后的标题", "更新失败"
    print("✓ 条目更新成功")

    assert vault.delete_entry(entry_id), "删除失败"
    assert vault.entry_count == 0, "删除后数量不为0"
    print("✓ 条目删除成功")

    print()


def test_locker():
    print("=== 测试锁定机制 ===")

    tmpdir = tempfile.mkdtemp()
    state_file = os.path.join(tmpdir, "lock_state.json")

    locker = LockManager(state_file, max_attempts=3, lock_duration=60)
    assert not locker.is_locked, "初始不应锁定"
    assert locker.remaining_attempts == 3, "初始尝试次数错误"
    print("✓ 初始状态正常")

    locker.record_failure()
    assert locker.remaining_attempts == 2, "失败计数错误"
    print("✓ 失败计数成功")

    locker.record_failure()
    locker.record_failure()
    assert locker.is_locked, "三次失败后应锁定"
    print("✓ 锁定触发成功")

    locker.record_success()
    assert not locker.is_locked, "成功后应解锁"
    assert locker.remaining_attempts == 3, "成功后计数应重置"
    print("✓ 成功重置成功")

    print()


def test_importer():
    print("=== 测试导入功能 ===")

    tmpdir = tempfile.mkdtemp()
    csv_file = os.path.join(tmpdir, "test.csv")

    csv_content = """url,username,password,name,note
https://example.com,user1,pass1,Example Site,Test note
https://test.org,user2,pass2,Test Site,Another note
"""
    with open(csv_file, "w", encoding="utf-8") as f:
        f.write(csv_content)

    result = import_file(csv_file)
    assert result.success_count > 0, "导入失败"
    print(f"✓ 导入成功: {result.success_count} 条目")
    print(f"  格式: {result.format_detected}")

    for entry in result.imported:
        print(f"    - {entry.title}: {entry.username}")

    print()


def main():
    print("密码管理器功能测试\n")

    try:
        test_crypto()
        test_entry()
        test_generator()
        test_totp()
        test_vault()
        test_locker()
        test_importer()

        print("=" * 50)
        print("所有测试通过！✓")
        print("=" * 50)
    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
