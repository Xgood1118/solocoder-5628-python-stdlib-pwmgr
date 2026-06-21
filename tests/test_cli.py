"""CLI 功能测试脚本 - 测试密码库完整流程"""

import os
import sys
import tempfile
import json
import subprocess
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pwmgr.vault import Vault
from pwmgr.entry import Entry, Category
from pwmgr.generator import PasswordGenerator


def run_cmd(vault_path, args, password=None, stdin_input=None):
    """运行 CLI 命令"""
    env = os.environ.copy()
    env["VAULT_PATH"] = vault_path

    cmd = [sys.executable, "main.py", "--vault", vault_path] + args

    if stdin_input:
        result = subprocess.run(
            cmd,
            input=stdin_input,
            capture_output=True,
            text=True,
            env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )
    else:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )

    return result.returncode, result.stdout, result.stderr


def test_cli():
    print("=== CLI 功能测试 ===\n")

    tmpdir = tempfile.mkdtemp()
    vault_path = os.path.join(tmpdir, "test_vault.dat")
    password = "testpass123"

    try:
        print("1. 测试 init 命令...")
        code, out, err = run_cmd(vault_path, ["init"], stdin_input=f"{password}\n{password}\n")
        if code == 0:
            print("   ✓ init 成功")
        else:
            print(f"   ✗ init 失败:", err)
            print("   stdout:", out)
            print("   stderr:", err)
            return False

        print("\n2. 测试 add 命令...")
        code, out, err = run_cmd(
            vault_path,
            ["add", "--title", "测试网站", "--username", "user1",
             "--password", "pass123", "--url", "https://test.com",
             "--notes", "测试备注", "--category", "login", "--tags", "work,test"],
            stdin_input=f"{password}\n"
        )
        if code == 0:
            print("   ✓ add 成功")
            print("   ", out.strip())
        else:
            print(f"   ✗ add 失败: {err}")
            return False

        print("\n3. 测试 list 命令...")
        code, out, err = run_cmd(vault_path, ["list"], stdin_input=f"{password}\n")
        if code == 0 and "测试网站" in out:
            print("   ✓ list 成功")
        else:
            print(f"   ✗ list 失败: {err}")
            print("   output:", out)
            return False

        print("\n4. 测试 JSON 输出...")
        code, out, err = run_cmd(vault_path, ["--json", "list"], stdin_input=f"{password}\n")
        if code == 0:
            try:
                data = json.loads(out)
                if isinstance(data, list) and len(data) > 0:
                    print("   ✓ JSON 输出成功")
                else:
                    print("   ✗ JSON 格式不正确")
                    return False
            except json.JSONDecodeError:
                print("   ✗ JSON 解析失败")
                return False
        else:
            print(f"   ✗ JSON 输出失败: {err}")
            return False

        print("\n5. 测试 search 命令...")
        code, out, err = run_cmd(vault_path, ["search", "测试"], stdin_input=f"{password}\n")
        if code == 0 and "测试网站" in out:
            print("   ✓ search 成功")
        else:
            print(f"   ✗ search 失败")
            return False

        print("\n6. 测试 gen 命令...")
        code, out, err = run_cmd(vault_path, ["gen", "--length", "20"])
        if code == 0:
            print("   ✓ gen 成功")
            print("   生成的密码:", out.strip().split("[")[0].strip())
        else:
            print(f"   ✗ gen 失败: {err}")
            return False

        print("\n7. 测试 stats 命令...")
        code, out, err = run_cmd(vault_path, ["stats"], stdin_input=f"{password}\n")
        if code == 0 and "总条目数" in out:
            print("   ✓ stats 成功")
        else:
            print(f"   ✗ stats 失败: {err}")
            return False

        print("\n8. 测试 lock 命令...")
        code, out, err = run_cmd(vault_path, ["lock"], stdin_input=f"{password}\n")
        if code == 0:
            print("   ✓ lock 成功")
        else:
            print(f"   ✗ lock 失败: {err}")
            return False

        print("\n9. 测试导出功能...")
        export_file = os.path.join(tmpdir, "export.csv")
        code, out, err = run_cmd(
            vault_path,
            ["export", export_file, "--format", "csv"],
            stdin_input=f"{password}\n"
        )
        if code == 0 and os.path.exists(export_file):
            print("   ✓ 导出成功")
            with open(export_file, "r", encoding="utf-8") as f:
                content = f.read()
                print(f"   导出文件内容预览:", content[:100])
        else:
            print(f"   ✗ 导出失败: {err}")
            print("   stdout:", out)
            return False

        print("\n10. 测试 change-password 命令...")
        new_password = "newpassword456"
        code, out, err = run_cmd(
            vault_path,
            ["change-password"],
            stdin_input=f"{password}\n{new_password}\n{new_password}\n"
        )
        if code == 0:
            print("   ✓ 修改密码成功")
        else:
            print(f"   ✗ 修改密码失败: {err}")
            print("   stdout:", out)
            return False

        print("\n11. 验证新密码可解锁...")
        code, out, err = run_cmd(vault_path, ["list"], stdin_input=f"{new_password}\n")
        if code == 0 and "测试网站" in out:
            print("   ✓ 新密码解锁成功")
        else:
            print(f"   ✗ 新密码解锁失败: {err}")
            return False

        print("\n" + "=" * 50)
        print("所有 CLI 测试通过！✓")
        print("=" * 50)
        return True

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    success = test_cli()
    sys.exit(0 if success else 1)
