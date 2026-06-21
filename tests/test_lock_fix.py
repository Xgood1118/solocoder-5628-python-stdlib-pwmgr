"""锁定机制修复验证测试"""

import os
import sys
import time
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pwmgr.locker import LockManager
from pwmgr.vault import Vault
from pwmgr.entry import Entry


def test_locker_three_failures_then_locked():
    """核心测试: 连续输错 3 次后锁定 5 分钟"""
    print("=== 测试: 连续输错 3 次锁定 5 分钟 ===")

    tmpdir = tempfile.mkdtemp()
    state_file = os.path.join(tmpdir, "lock_state.json")

    try:
        locker = LockManager(state_file, max_attempts=3, lock_duration=300)

        assert not locker.is_locked, "初始不应锁定"
        assert locker.remaining_attempts == 3, f"初始应有 3 次机会，实际 {locker.remaining_attempts}"
        print(f"  初始状态: 剩余尝试 {locker.remaining_attempts}")

        locker.record_failure()
        assert not locker.is_locked, "第 1 次失败后不应锁定"
        assert locker.remaining_attempts == 2, f"第 1 次失败后应剩 2 次，实际 {locker.remaining_attempts}"
        print(f"  第 1 次错误: 剩余尝试 {locker.remaining_attempts}")

        locker.record_failure()
        assert not locker.is_locked, "第 2 次失败后不应锁定"
        assert locker.remaining_attempts == 1, f"第 2 次失败后应剩 1 次，实际 {locker.remaining_attempts}"
        print(f"  第 2 次错误: 剩余尝试 {locker.remaining_attempts}")

        locker.record_failure()
        assert locker.is_locked, "第 3 次失败后应锁定！"
        assert locker.remaining_lock_time > 0, "锁定时间应大于 0"
        print(f"  第 3 次错误: 已锁定！剩余锁定时间 {locker.remaining_lock_time}s")
        print(f"  状态消息: {locker.get_status_message()}")

        print("  ✓ 连续输错 3 次后成功锁定 5 分钟")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()


def test_locker_failed_attempts_not_reset_on_lock():
    """测试: 锁定后失败计数不应被重置"""
    print("=== 测试: 锁定后失败计数不重置 ===")

    tmpdir = tempfile.mkdtemp()
    state_file = os.path.join(tmpdir, "lock_state.json")

    try:
        locker = LockManager(state_file, max_attempts=3, lock_duration=300)

        locker.record_failure()
        locker.record_failure()
        locker.record_failure()

        assert locker.is_locked, "应处于锁定状态"
        assert locker.failed_attempts == 3, f"锁定后失败计数应为 3，实际 {locker.failed_attempts}"
        print(f"  锁定后 failed_attempts={locker.failed_attempts} (应为 3)")

        print("  ✓ 锁定后失败计数未被重置")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()


def test_locker_auto_unlock_resets_counter():
    """测试: 锁定到期后自动解锁并重置计数"""
    print("=== 测试: 锁定到期后自动重置 ===")

    tmpdir = tempfile.mkdtemp()
    state_file = os.path.join(tmpdir, "lock_state.json")

    try:
        locker = LockManager(state_file, max_attempts=3, lock_duration=1)

        locker.record_failure()
        locker.record_failure()
        locker.record_failure()
        assert locker.is_locked, "应处于锁定状态"

        print(f"  已锁定，等待 2 秒让锁定到期...")
        time.sleep(2)

        assert not locker.is_locked, "锁定到期后应自动解锁"
        assert locker.failed_attempts == 0, f"解锁后失败计数应为 0，实际 {locker.failed_attempts}"
        assert locker.remaining_attempts == 3, f"解锁后应有 3 次机会，实际 {locker.remaining_attempts}"
        print(f"  锁定到期后: is_locked={locker.is_locked}, failed_attempts={locker.failed_attempts}, remaining={locker.remaining_attempts}")

        print("  ✓ 锁定到期后自动解锁并重置计数")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()


def test_locker_success_resets_everything():
    """测试: 成功解锁重置所有状态"""
    print("=== 测试: 成功解锁重置状态 ===")

    tmpdir = tempfile.mkdtemp()
    state_file = os.path.join(tmpdir, "lock_state.json")

    try:
        locker = LockManager(state_file, max_attempts=3, lock_duration=300)

        locker.record_failure()
        locker.record_failure()
        assert locker.remaining_attempts == 1

        locker.record_success()
        assert locker.failed_attempts == 0
        assert locker.remaining_attempts == 3
        print(f"  成功后: failed_attempts={locker.failed_attempts}, remaining={locker.remaining_attempts}")

        print("  ✓ 成功解锁后重置所有状态")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()


def test_locker_state_persistence():
    """测试: 锁定状态持久化到文件"""
    print("=== 测试: 锁定状态持久化 ===")

    tmpdir = tempfile.mkdtemp()
    state_file = os.path.join(tmpdir, "lock_state.json")

    try:
        locker1 = LockManager(state_file, max_attempts=3, lock_duration=300)
        locker1.record_failure()
        locker1.record_failure()
        locker1.record_failure()
        assert locker1.is_locked

        locker2 = LockManager(state_file, max_attempts=3, lock_duration=300)
        assert locker2.is_locked, "新实例应从文件读取锁定状态"
        assert locker2.failed_attempts == 3, f"新实例失败计数应为 3，实际 {locker2.failed_attempts}"
        print(f"  新实例: is_locked={locker2.is_locked}, failed_attempts={locker2.failed_attempts}")

        print("  ✓ 锁定状态持久化正常")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()


def test_vault_wrong_password_triggers_lock():
    """测试: 用 Vault 验证连续输错密码触发锁定"""
    print("=== 测试: Vault 连续输错密码触发锁定 ===")

    tmpdir = tempfile.mkdtemp()
    vault_path = os.path.join(tmpdir, "vault.dat")
    state_file = os.path.join(tmpdir, "lock_state.json")

    try:
        vault = Vault(vault_path)
        master_password = "correctpassword123"
        vault.create(master_password)
        vault.add_entry(Entry(title="test", username="user", password="pass"))
        vault.save()
        vault.lock()

        locker = LockManager(state_file, max_attempts=3, lock_duration=300)

        assert vault.unlock("wrong1") == False
        locker.record_failure()
        assert not locker.is_locked
        print(f"  第 1 次错误: remaining={locker.remaining_attempts}")

        assert vault.unlock("wrong2") == False
        locker.record_failure()
        assert not locker.is_locked
        print(f"  第 2 次错误: remaining={locker.remaining_attempts}")

        assert vault.unlock("wrong3") == False
        locker.record_failure()
        assert locker.is_locked, "3 次失败后应锁定！"
        print(f"  第 3 次错误: 已锁定！锁定时间 {locker.remaining_lock_time}s")

        assert vault.unlock("correctpassword123") == True
        locker.record_success()
        assert not locker.is_locked
        assert locker.failed_attempts == 0
        print(f"  正确密码解锁后: failed_attempts={locker.failed_attempts}")

        print("  ✓ Vault + LockManager 集成测试通过")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()


def test_locker_remaining_attempts_message():
    """测试: 状态消息正确显示剩余尝试次数"""
    print("=== 测试: 状态消息 ===")

    tmpdir = tempfile.mkdtemp()
    state_file = os.path.join(tmpdir, "lock_state.json")

    try:
        locker = LockManager(state_file, max_attempts=3, lock_duration=300)

        msg = locker.get_status_message()
        assert "3" in msg, f"初始消息应包含 3，实际: {msg}"
        print(f"  初始: {msg}")

        locker.record_failure()
        msg = locker.get_status_message()
        assert "2" in msg, f"1 次失败后消息应包含 2，实际: {msg}"
        print(f"  1 次失败: {msg}")

        locker.record_failure()
        msg = locker.get_status_message()
        assert "1" in msg, f"2 次失败后消息应包含 1，实际: {msg}"
        print(f"  2 次失败: {msg}")

        locker.record_failure()
        msg = locker.get_status_message()
        assert "锁定" in msg, f"3 次失败后消息应包含'锁定'，实际: {msg}"
        print(f"  3 次失败: {msg}")

        print("  ✓ 状态消息正确")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print()


def main():
    print("锁定机制修复验证测试\n")

    try:
        test_locker_three_failures_then_locked()
        test_locker_failed_attempts_not_reset_on_lock()
        test_locker_auto_unlock_resets_counter()
        test_locker_success_resets_everything()
        test_locker_state_persistence()
        test_vault_wrong_password_triggers_lock()
        test_locker_remaining_attempts_message()

        print("=" * 60)
        print("所有锁定机制测试通过！✓")
        print("=" * 60)
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
