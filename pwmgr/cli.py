"""CLI 主入口 - 交互模式和单条命令模式"""

import sys
import os
import json
import argparse
import getpass
import time
from pathlib import Path
from typing import Optional, List

from .vault import Vault
from .entry import Entry, Category
from .generator import PasswordGenerator, evaluate_password_strength, get_strength_bar
from .totp import TOTPGenerator, format_code
from .clipboard import copy_to_clipboard, clear_clipboard
from .locker import LockManager
from .importer import import_file, detect_format
from .exporter import export_to_csv, export_to_json


DEFAULT_VAULT_PATH = os.path.expanduser("~/.pwmgr/vault.dat")
DEFAULT_LOCK_STATE_PATH = os.path.expanduser("~/.pwmgr/lock_state.json")


class PasswordManagerCLI:
    """密码管理器 CLI"""

    def __init__(self, vault_path: str = None):
        self.vault_path = vault_path or DEFAULT_VAULT_PATH
        self.lock_state_path = os.path.join(
            os.path.dirname(self.vault_path),
            "lock_state.json"
        )
        self.vault = Vault(self.vault_path)
        self.locker = LockManager(self.lock_state_path)
        self.clipboard_clear_delay = 5
        self.json_output = False
        self.interactive = False

    def run(self, args: list = None):
        """运行 CLI"""
        if args is None:
            args = sys.argv[1:]

        parser = self._build_parser()
        parsed_args = parser.parse_args(args)

        self.json_output = getattr(parsed_args, "json", False)

        if not parsed_args.command:
            self._interactive_mode()
            return

        command = parsed_args.command
        try:
            if command == "init":
                self._cmd_init(parsed_args)
            elif command == "list":
                self._cmd_list(parsed_args)
            elif command == "get":
                self._cmd_get(parsed_args)
            elif command == "add":
                self._cmd_add(parsed_args)
            elif command == "edit":
                self._cmd_edit(parsed_args)
            elif command == "delete":
                self._cmd_delete(parsed_args)
            elif command == "search":
                self._cmd_search(parsed_args)
            elif command == "gen":
                self._cmd_gen(parsed_args)
            elif command == "import":
                self._cmd_import(parsed_args)
            elif command == "export":
                self._cmd_export(parsed_args)
            elif command == "stats":
                self._cmd_stats(parsed_args)
            elif command == "lock":
                self._cmd_lock(parsed_args)
            elif command == "change-password":
                self._cmd_change_password(parsed_args)
            elif command == "totp":
                self._cmd_totp(parsed_args)
            else:
                self._error(f"未知命令: {command}")
        except KeyboardInterrupt:
            if self.json_output:
                print(json.dumps({"status": "cancelled"}))
            else:
                print("\n操作已取消")
        except Exception as e:
            self._error(str(e))

    def _build_parser(self) -> argparse.ArgumentParser:
        """构建参数解析器"""
        parser = argparse.ArgumentParser(
            prog="pwmgr",
            description="本地密码管理器 - 安全存储您的密码",
        )
        parser.add_argument("--json", action="store_true", help="JSON 格式输出")
        parser.add_argument("--vault", help="密码库文件路径")

        subparsers = parser.add_subparsers(dest="command", help="可用命令")

        subparsers.add_parser("init", help="初始化新密码库")

        list_parser = subparsers.add_parser("list", help="列出所有条目")
        list_parser.add_argument("--category", help="按分类筛选")
        list_parser.add_argument("--tag", help="按标签筛选")
        list_parser.add_argument("--folder", help="按文件夹筛选")

        get_parser = subparsers.add_parser("get", help="查看条目详情")
        get_parser.add_argument("id", help="条目 ID 或标题")
        get_parser.add_argument("--clip", action="store_true", help="复制密码到剪贴板")
        get_parser.add_argument("--show-password", action="store_true", help="显示密码")

        add_parser = subparsers.add_parser("add", help="添加新条目")
        add_parser.add_argument("--title", help="标题")
        add_parser.add_argument("--username", help="用户名")
        add_parser.add_argument("--password", help="密码")
        add_parser.add_argument("--url", help="URL")
        add_parser.add_argument("--notes", help="备注")
        add_parser.add_argument("--category", help="分类")
        add_parser.add_argument("--tags", help="标签（逗号分隔）")
        add_parser.add_argument("--generate", action="store_true", help="生成密码")
        add_parser.add_argument("--gen-length", type=int, default=16, help="生成密码长度")

        edit_parser = subparsers.add_parser("edit", help="编辑条目")
        edit_parser.add_argument("id", help="条目 ID 或标题")
        edit_parser.add_argument("--title", help="标题")
        edit_parser.add_argument("--username", help="用户名")
        edit_parser.add_argument("--password", help="新密码")
        edit_parser.add_argument("--url", help="URL")
        edit_parser.add_argument("--notes", help="备注")
        edit_parser.add_argument("--category", help="分类")
        edit_parser.add_argument("--tags", help="标签（逗号分隔）")
        edit_parser.add_argument("--generate", action="store_true", help="生成新密码")
        edit_parser.add_argument("--gen-length", type=int, default=16, help="生成密码长度")

        delete_parser = subparsers.add_parser("delete", help="删除条目")
        delete_parser.add_argument("id", help="条目 ID 或标题")
        delete_parser.add_argument("-f", "--force", action="store_true", help="不确认直接删除")

        search_parser = subparsers.add_parser("search", help="搜索条目")
        search_parser.add_argument("keyword", help="搜索关键词")

        gen_parser = subparsers.add_parser("gen", help="生成密码")
        gen_parser.add_argument("--length", "-l", type=int, default=16, help="密码长度")
        gen_parser.add_argument("--no-lower", action="store_true", help="不包含小写字母")
        gen_parser.add_argument("--no-upper", action="store_true", help="不包含大写字母")
        gen_parser.add_argument("--no-digits", action="store_true", help="不包含数字")
        gen_parser.add_argument("--no-symbols", action="store_true", help="不包含特殊符号")
        gen_parser.add_argument("--exclude-ambiguous", action="store_true", help="排除易混淆字符")
        gen_parser.add_argument("--clip", action="store_true", help="复制到剪贴板")
        gen_parser.add_argument("--count", "-n", type=int, default=1, help="生成数量")

        import_parser = subparsers.add_parser("import", help="导入密码")
        import_parser.add_argument("file", help="导入文件路径")
        import_parser.add_argument("--format", help="文件格式（自动检测）")

        export_parser = subparsers.add_parser("export", help="导出密码")
        export_parser.add_argument("file", help="导出文件路径")
        export_parser.add_argument("--format", default="csv", help="导出格式 (csv/json)")
        export_parser.add_argument("--encrypted", action="store_true", help="加密导出")
        export_parser.add_argument("--password", help="加密密码")

        subparsers.add_parser("stats", help="显示密码库统计")

        subparsers.add_parser("lock", help="锁定密码库")

        subparsers.add_parser("change-password", help="修改主密码")

        totp_parser = subparsers.add_parser("totp", help="TOTP 验证码")
        totp_parser.add_argument("id", nargs="?", help="条目 ID 或标题")
        totp_parser.add_argument("--add", action="store_true", help="添加 TOTP")
        totp_parser.add_argument("--secret", help="TOTP 密钥")
        totp_parser.add_argument("--issuer", help="发行者")
        totp_parser.add_argument("--clip", action="store_true", help="复制验证码到剪贴板")

        return parser

    def _interactive_mode(self):
        """交互模式"""
        self.interactive = True

        if not self.vault.exists():
            self._print_message("密码库不存在，正在初始化...")
            self._init_interactive()
            return

        if not self._unlock_interactive():
            return

        self._print_message(f"欢迎使用密码管理器，共 {self.vault.entry_count} 个条目")
        self._print_help()

        while True:
            try:
                if self.vault.check_auto_lock():
                    self._print_warning("长时间无操作，密码库已锁定")
                    if not self._unlock_interactive():
                        break

                cmd = input("\n[pwmgr] > ").strip()
                if not cmd:
                    continue

                if self.vault.check_auto_lock():
                    self._print_warning("长时间无操作，密码库已锁定")
                    if not self._unlock_interactive():
                        continue

                if cmd in ("quit", "exit", "q"):
                    self._print_message("再见！")
                    break
                elif cmd == "help":
                    self._print_help()
                elif cmd.startswith("list"):
                    self._interactive_list(cmd)
                elif cmd.startswith("get"):
                    self._interactive_get(cmd)
                elif cmd.startswith("add"):
                    self._interactive_add()
                elif cmd.startswith("edit"):
                    self._interactive_edit(cmd)
                elif cmd.startswith("delete"):
                    self._interactive_delete(cmd)
                elif cmd.startswith("search"):
                    self._interactive_search(cmd)
                elif cmd.startswith("gen"):
                    self._interactive_gen(cmd)
                elif cmd == "stats":
                    self._show_stats()
                elif cmd == "lock":
                    self.vault.lock()
                    self._print_message("密码库已锁定")
                    if not self._unlock_interactive():
                        break
                elif cmd == "change-password":
                    self._interactive_change_password()
                elif cmd.startswith("totp"):
                    self._interactive_totp(cmd)
                elif cmd.startswith("import"):
                    self._interactive_import(cmd)
                elif cmd.startswith("export"):
                    self._interactive_export(cmd)
                else:
                    self._print_error(f"未知命令: {cmd}，输入 help 查看帮助")
            except KeyboardInterrupt:
                self._print_message("\n再见！")
                break
            except Exception as e:
                self._print_error(f"错误: {e}")

    def _print_help(self):
        """打印帮助信息"""
        help_text = """
可用命令:
  list [--category cat] [--tag tag]  列出条目
  get <id|title>                      查看条目详情
  add                                 添加新条目
  edit <id|title>                     编辑条目
  delete <id|title>                   删除条目
  search <keyword>                    搜索条目
  gen [length]                        生成密码
  totp <id|title>                     查看 TOTP 验证码
  stats                               显示统计信息
  import <file>                       导入密码
  export <file>                       导出密码
  change-password                     修改主密码
  lock                                锁定密码库
  help                                显示帮助
  quit/exit/q                         退出
"""
        if self.json_output:
            print(json.dumps({"commands": help_text.strip().split("\n")}))
        else:
            print(help_text)

    def _unlock_interactive(self) -> bool:
        """交互式解锁"""
        if self.locker.is_locked:
            self._print_warning(self.locker.get_status_message())
            return False

        attempts = 0
        while attempts < 3:
            try:
                master_password = getpass.getpass("请输入主密码: ")
            except (EOFError, KeyboardInterrupt):
                return False

            if not master_password:
                self._print_warning("密码不能为空")
                continue

            if self.vault.unlock(master_password):
                self.locker.record_success()
                return True
            else:
                attempts += 1
                self.locker.record_failure()
                if self.locker.is_locked:
                    self._print_error(self.locker.get_status_message())
                    return False
                else:
                    self._print_warning(f"密码错误，{self.locker.get_status_message()}")
        return False

    def _init_interactive(self):
        """交互式初始化"""
        print("=== 初始化密码库 ===")
        while True:
            try:
                password1 = getpass.getpass("请设置主密码: ")
            except (EOFError, KeyboardInterrupt):
                return

            if len(password1) < 6:
                self._print_warning("主密码至少 6 个字符")
                continue

            try:
                password2 = getpass.getpass("请再次输入主密码: ")
            except (EOFError, KeyboardInterrupt):
                return

            if password1 == password2:
                self.vault.create(password1)
                self._print_success("密码库创建成功！")
                self._interactive_mode_after_init()
                return
            else:
                self._print_warning("两次输入的密码不一致，请重试")

    def _interactive_mode_after_init(self):
        """初始化后的交互模式"""
        self._print_message(f"欢迎使用密码管理器")
        self._print_help()

        while True:
            try:
                cmd = input("\n[pwmgr] > ").strip()
                if not cmd:
                    continue

                if cmd in ("quit", "exit", "q"):
                    self._print_message("再见！")
                    break
                elif cmd == "help":
                    self._print_help()
                elif cmd.startswith("list"):
                    self._interactive_list(cmd)
                elif cmd.startswith("get"):
                    self._interactive_get(cmd)
                elif cmd.startswith("add"):
                    self._interactive_add()
                elif cmd.startswith("edit"):
                    self._interactive_edit(cmd)
                elif cmd.startswith("delete"):
                    self._interactive_delete(cmd)
                elif cmd.startswith("search"):
                    self._interactive_search(cmd)
                elif cmd.startswith("gen"):
                    self._interactive_gen(cmd)
                elif cmd == "stats":
                    self._show_stats()
                elif cmd == "lock":
                    self.vault.lock()
                    self._print_message("密码库已锁定")
                    break
                elif cmd == "change-password":
                    self._interactive_change_password()
                elif cmd.startswith("totp"):
                    self._interactive_totp(cmd)
                elif cmd.startswith("import"):
                    self._interactive_import(cmd)
                elif cmd.startswith("export"):
                    self._interactive_export(cmd)
                else:
                    self._print_error(f"未知命令: {cmd}，输入 help 查看帮助")
            except KeyboardInterrupt:
                self._print_message("\n再见！")
                break

    def _interactive_list(self, cmd: str):
        """交互式 list 命令"""
        parts = cmd.split()
        category = None
        tag = None
        folder = None

        i = 1
        while i < len(parts):
            if parts[i] == "--category" and i + 1 < len(parts):
                category = Category.from_str(parts[i + 1])
                i += 2
            elif parts[i] == "--tag" and i + 1 < len(parts):
                tag = parts[i + 1]
                i += 2
            elif parts[i] == "--folder" and i + 1 < len(parts):
                folder = parts[i + 1]
                i += 2
            else:
                i += 1

        entries = self.vault.list_entries(category=category, tag=tag, folder=folder)
        self._display_entries(entries)

    def _interactive_get(self, cmd: str):
        """交互式 get 命令"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            self._print_warning("请输入条目 ID 或标题")
            return

        identifier = parts[1].strip()
        entry = self._find_entry(identifier)
        if entry:
            self._display_entry(entry)
        else:
            self._print_error(f"未找到条目: {identifier}")

    def _interactive_add(self):
        """交互式添加条目"""
        print("\n=== 添加新条目 ===")

        title = input("标题: ").strip()
        if not title:
            self._print_warning("标题不能为空")
            return

        username = input("用户名: ").strip()
        password = input("密码 (留空自动生成): ").strip()

        if not password:
            gen = PasswordGenerator()
            password = gen.generate()
            self._print_message(f"已生成密码: {password}")

        url = input("URL: ").strip()
        notes = input("备注: ").strip()
        category_str = input("分类 (login/credit_card/secure_note/ssh_key/wifi/software_license): ").strip()
        category = Category.from_str(category_str) if category_str else Category.LOGIN
        tags_str = input("标签 (逗号分隔): ").strip()
        tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

        entry = Entry(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            category=category,
            tags=tags,
        )

        entry_id = self.vault.add_entry(entry)
        self.vault.save()
        self._print_success(f"条目已添加，ID: {entry_id}")

    def _interactive_edit(self, cmd: str):
        """交互式编辑条目"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            self._print_warning("请输入条目 ID 或标题")
            return

        identifier = parts[1].strip()
        entry = self._find_entry(identifier)
        if not entry:
            self._print_error(f"未找到条目: {identifier}")
            return

        print("\n=== 编辑条目 ===")
        print(f"当前标题: {entry.title}")
        new_title = input("新标题 (留空不修改): ").strip()
        if new_title:
            entry.title = new_title

        print(f"当前用户名: {entry.username}")
        new_username = input("新用户名 (留空不修改): ").strip()
        if new_username:
            entry.username = new_username

        print("当前密码: ********")
        new_password = input("新密码 (留空不修改, 输入 generate 生成): ").strip()
        if new_password == "generate":
            gen = PasswordGenerator()
            new_password = gen.generate()
            self._print_message(f"已生成密码: {new_password}")
        if new_password:
            entry.update_password(new_password)

        print(f"当前 URL: {entry.url}")
        new_url = input("新 URL (留空不修改): ").strip()
        if new_url:
            entry.url = new_url

        print(f"当前备注: {entry.notes}")
        new_notes = input("新备注 (留空不修改): ").strip()
        if new_notes:
            entry.notes = new_notes

        self.vault.update_entry(entry)
        self.vault.save()
        self._print_success("条目已更新")

    def _interactive_delete(self, cmd: str):
        """交互式删除条目"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            self._print_warning("请输入条目 ID 或标题")
            return

        identifier = parts[1].strip()
        entry = self._find_entry(identifier)
        if not entry:
            self._print_error(f"未找到条目: {identifier}")
            return

        confirm = input(f"确定要删除条目 '{entry.title}' 吗？(y/N): ").strip().lower()
        if confirm == "y":
            self.vault.delete_entry(entry.id)
            self.vault.save()
            self._print_success("条目已删除")
        else:
            self._print_message("已取消删除")

    def _interactive_search(self, cmd: str):
        """交互式搜索"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            self._print_warning("请输入搜索关键词")
            return

        keyword = parts[1].strip()
        results = self.vault.search_entries(keyword)
        self._display_entries(results)
        if results:
            self._print_message(f"找到 {len(results)} 个结果")
        else:
            self._print_message("没有找到匹配的条目")

    def _interactive_gen(self, cmd: str):
        """交互式生成密码"""
        parts = cmd.split()
        length = 16
        if len(parts) >= 2:
            try:
                length = int(parts[1])
            except ValueError:
                pass

        gen = PasswordGenerator(length=length)
        password = gen.generate()
        strength = evaluate_password_strength(password)

        if self.json_output:
            print(json.dumps({
                "password": password,
                "strength": {
                    "score": strength.score,
                    "level": strength.level,
                    "feedback": strength.feedback,
                }
            }))
        else:
            print(f"\n生成的密码: {password}")
            print(f"强度: {get_strength_bar(strength.score)} {strength.score}/100 ({strength.level})")

        if input("复制到剪贴板？(y/N): ").strip().lower() == "y":
            if copy_to_clipboard(password, self.clipboard_clear_delay):
                self._print_success(f"已复制到剪贴板，{self.clipboard_clear_delay} 秒后自动清除")
            else:
                self._print_warning("无法复制到剪贴板")

    def _interactive_change_password(self):
        """交互式修改主密码"""
        print("\n=== 修改主密码 ===")

        old_password = getpass.getpass("请输入当前主密码: ")
        if not self.vault.unlock(old_password):
            self._print_error("当前密码错误")
            return

        new_password1 = getpass.getpass("请输入新主密码: ")
        if len(new_password1) < 6:
            self._print_warning("主密码至少 6 个字符")
            return

        new_password2 = getpass.getpass("请再次输入新主密码: ")
        if new_password1 != new_password2:
            self._print_error("两次输入的密码不一致")
            return

        if self.vault.change_master_password(old_password, new_password1):
            self._print_success("主密码修改成功")
        else:
            self._print_error("修改失败")

    def _interactive_totp(self, cmd: str):
        """交互式 TOTP"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            self._print_warning("请输入条目 ID 或标题")
            return

        identifier = parts[1].strip()
        entry = self._find_entry(identifier)
        if not entry:
            self._print_error(f"未找到条目: {identifier}")
            return

        if not entry.totp.is_enabled:
            self._print_warning("该条目未启用 TOTP")
            add = input("是否添加 TOTP？(y/N): ").strip().lower()
            if add == "y":
                secret = input("请输入 TOTP 密钥 (base32): ").strip()
                if secret:
                    entry.totp.secret = secret
                    entry.totp.issuer = input("发行者 (可选): ").strip()
                    recovery_codes = TOTPGenerator(secret).generate_recovery_codes()
                    entry.totp.recovery_codes = recovery_codes
                    self.vault.update_entry(entry)
                    self.vault.save()
                    self._print_success("TOTP 已添加")
                    print("\n备用恢复码（请妥善保存）:")
                    for code in recovery_codes:
                        print(f"  {code}")
            return

        totp_gen = TOTPGenerator(
            secret=entry.totp.secret,
            digits=entry.totp.digits,
            period=entry.totp.period,
            issuer=entry.totp.issuer,
        )

        try:
            print("\n按 Ctrl+C 返回")
            while True:
                code = totp_gen.generate_code()
                progress = totp_gen.progress_bar()
                remaining = totp_gen.time_remaining()

                if self.json_output:
                    print(json.dumps({
                        "code": code,
                        "remaining": remaining,
                        "progress": progress,
                    }), end="\r")
                else:
                    print(f"\r验证码: {format_code(code)}  {progress}", end="", flush=True)

                time.sleep(1)
        except KeyboardInterrupt:
            print("\n")

    def _interactive_import(self, cmd: str):
        """交互式导入"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            self._print_warning("请输入导入文件路径")
            return

        file_path = parts[1].strip()
        fmt = detect_format(file_path)

        self._print_message(f"检测到格式: {fmt}")
        confirm = input(f"确认导入 {file_path}？(y/N): ").strip().lower()
        if confirm != "y":
            return

        result = import_file(file_path, fmt)
        if result.success_count > 0:
            for entry in result.imported:
                self.vault.add_entry(entry)
            self.vault.save()
            self._print_success(f"成功导入 {result.success_count} 个条目")
        else:
            self._print_error("导入失败")

        if result.errors:
            for error in result.errors:
                self._print_error(f"  错误: {error}")

    def _interactive_export(self, cmd: str):
        """交互式导出"""
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            self._print_warning("请输入导出文件路径")
            return

        file_path = parts[1].strip()
        entries = self.vault.list_entries()

        encrypted = input("是否加密导出？(y/N): ").strip().lower() == "y"
        password = None
        if encrypted:
            password = getpass.getpass("请输入导出密码: ")

        if file_path.endswith(".json"):
            result = export_to_json(entries, file_path, encrypted, password)
        else:
            result = export_to_csv(entries, file_path, encrypted, password)

        if not encrypted:
            self._print_warning("警告: 未加密导出包含明文密码，请妥善保管！")

        self._print_success(f"已导出 {result.exported_count} 个条目到 {file_path}")

    def _find_entry(self, identifier: str) -> Optional[Entry]:
        """根据 ID 或标题查找条目"""
        entry = self.vault.get_entry(identifier)
        if entry:
            return entry
        return self.vault.get_entry_by_title(identifier)

    def _display_entries(self, entries: List[Entry]):
        """显示条目列表"""
        if self.json_output:
            print(json.dumps([e.to_dict() for e in entries], ensure_ascii=False))
            return

        if not entries:
            print("(空)")
            return

        for i, entry in enumerate(entries, 1):
            cat_display = Category.display_name(entry.category)
            print(f"  [{entry.id[:8]}] {entry.title}")
            print(f"      用户名: {entry.username or '-'}")
            print(f"      URL: {entry.url or '-'}")
            print(f"      分类: {cat_display} | 标签: {', '.join(entry.tags) if entry.tags else '-'}")
            if entry.totp.is_enabled:
                print(f"      🔐 TOTP 已启用")
            print()

    def _display_entry(self, entry: Entry):
        """显示条目详情"""
        if self.json_output:
            print(json.dumps(entry.to_dict(), ensure_ascii=False))
            return

        print(f"\n=== {entry.title} ===")
        print(f"  ID: {entry.id}")
        print(f"  分类: {Category.display_name(entry.category)}")
        print(f"  用户名: {entry.username}")
        print(f"  密码: {'*' * len(entry.password) if entry.password else '(空)'}")
        print(f"  URL: {entry.url}")
        print(f"  备注: {entry.notes or '(无)'}")

        if entry.tags:
            print(f"  标签: {', '.join(entry.tags)}")

        if entry.folder:
            print(f"  文件夹: {entry.folder}")

        if entry.custom_fields:
            print("  自定义字段:")
            for field in entry.custom_fields:
                print(f"    {field.name}: {field.value if field.type != 'password' else '***'}")

        if entry.totp.is_enabled:
            totp_gen = TOTPGenerator(
                secret=entry.totp.secret,
                digits=entry.totp.digits,
                period=entry.totp.period,
            )
            code = totp_gen.generate_code()
            remaining = totp_gen.time_remaining()
            print(f"  TOTP: {format_code(code)} (剩余 {remaining}s)")

        if entry.password_history:
            print(f"  密码历史: {len(entry.password_history)} 条记录")

        print(f"  创建时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.created_at))}")
        print(f"  更新时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.updated_at))}")

    def _show_stats(self):
        """显示统计信息"""
        stats = self.vault.get_statistics()

        if self.json_output:
            print(json.dumps(stats, ensure_ascii=False))
            return

        print("\n=== 密码库统计 ===")
        print(f"  总条目数: {stats['total_entries']}")
        print(f"  标签数: {stats['total_tags']}")
        print(f"  文件夹数: {stats['total_folders']}")
        print(f"  启用 TOTP: {stats['totp_enabled']}")
        print(f"  弱密码: {stats['weak_passwords']}")
        print(f"  重复密码组: {stats['duplicate_password_groups']}")
        print(f"  重复密码总数: {stats['duplicate_password_count']}")
        print("\n  按分类:")
        for cat, count in stats["by_category"].items():
            cat_enum = Category.from_str(cat)
            print(f"    {Category.display_name(cat_enum)}: {count}")

    def _cmd_init(self, args):
        """init 命令"""
        if self.vault.exists():
            self._error("密码库已存在")
            return

        try:
            password = getpass.getpass("请设置主密码: ")
            password2 = getpass.getpass("请再次输入主密码: ")
        except (EOFError, KeyboardInterrupt):
            self._error("已取消")
            return

        if password != password2:
            self._error("两次输入的密码不一致")
            return

        if len(password) < 6:
            self._error("主密码至少 6 个字符")
            return

        self.vault.create(password)
        self._success("密码库创建成功")

    def _cmd_list(self, args):
        """list 命令"""
        self._ensure_unlocked()

        category = None
        if args.category:
            category = Category.from_str(args.category)

        tag = getattr(args, "tag", None)
        folder = getattr(args, "folder", None)

        entries = self.vault.list_entries(category=category, tag=tag, folder=folder)
        self._display_entries(entries)

    def _cmd_get(self, args):
        """get 命令"""
        self._ensure_unlocked()

        entry = self._find_entry(args.id)
        if not entry:
            self._error(f"未找到条目: {args.id}")
            return

        if args.clip:
            if copy_to_clipboard(entry.password, self.clipboard_clear_delay):
                if not self.json_output:
                    self._success(f"密码已复制到剪贴板，{self.clipboard_clear_delay} 秒后自动清除")
            else:
                self._error("无法复制到剪贴板")
            return

        self._display_entry(entry)

    def _cmd_add(self, args):
        """add 命令"""
        self._ensure_unlocked()

        title = args.title
        if not title:
            title = input("标题: ").strip()
        if not title:
            self._error("标题不能为空")
            return

        password = args.password
        if args.generate or not password:
            gen = PasswordGenerator(length=args.gen_length)
            password = gen.generate()
            if not self.json_output:
                print(f"生成的密码: {password}")

        username = args.username or ""
        url = args.url or ""
        notes = args.notes or ""
        category = Category.from_str(args.category) if args.category else Category.LOGIN
        tags = [t.strip() for t in args.tags.split(",")] if args.tags else []

        entry = Entry(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            category=category,
            tags=tags,
        )

        entry_id = self.vault.add_entry(entry)
        self.vault.save()
        self._success(f"条目已添加，ID: {entry_id}")

    def _cmd_edit(self, args):
        """edit 命令"""
        self._ensure_unlocked()

        entry = self._find_entry(args.id)
        if not entry:
            self._error(f"未找到条目: {args.id}")
            return

        if args.title:
            entry.title = args.title
        if args.username:
            entry.username = args.username
        if args.password:
            entry.update_password(args.password)
        if args.generate:
            gen = PasswordGenerator(length=args.gen_length)
            new_pwd = gen.generate()
            entry.update_password(new_pwd)
            if not self.json_output:
                print(f"生成的新密码: {new_pwd}")
        if args.url:
            entry.url = args.url
        if args.notes:
            entry.notes = args.notes
        if args.category:
            entry.category = Category.from_str(args.category)
        if args.tags:
            entry.tags = [t.strip() for t in args.tags.split(",")]

        self.vault.update_entry(entry)
        self.vault.save()
        self._success("条目已更新")

    def _cmd_delete(self, args):
        """delete 命令"""
        self._ensure_unlocked()

        entry = self._find_entry(args.id)
        if not entry:
            self._error(f"未找到条目: {args.id}")
            return

        if not args.force:
            confirm = input(f"确定要删除 '{entry.title}' 吗？(y/N): ").strip().lower()
            if confirm != "y":
                self._message("已取消删除")
                return

        self.vault.delete_entry(entry.id)
        self.vault.save()
        self._success("条目已删除")

    def _cmd_search(self, args):
        """search 命令"""
        self._ensure_unlocked()

        results = self.vault.search_entries(args.keyword)
        self._display_entries(results)

    def _cmd_gen(self, args):
        """gen 命令"""
        gen = PasswordGenerator(
            length=args.length,
            use_lowercase=not args.no_lower,
            use_uppercase=not args.no_upper,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            exclude_ambiguous=args.exclude_ambiguous,
        )

        passwords = []
        for _ in range(args.count):
            passwords.append(gen.generate())

        if args.clip and args.count == 1:
            if copy_to_clipboard(passwords[0], self.clipboard_clear_delay):
                if not self.json_output:
                    self._success(f"已复制到剪贴板，{self.clipboard_clear_delay} 秒后自动清除")
            else:
                self._error("无法复制到剪贴板")

        if self.json_output:
            result = []
            for pwd in passwords:
                strength = evaluate_password_strength(pwd)
                result.append({
                    "password": pwd,
                    "strength": {
                        "score": strength.score,
                        "level": strength.level,
                    }
                })
            print(json.dumps(result, ensure_ascii=False))
        else:
            for i, pwd in enumerate(passwords):
                strength = evaluate_password_strength(pwd)
                print(f"{pwd}  [{get_strength_bar(strength.score)} {strength.score}]")

    def _cmd_import(self, args):
        """import 命令"""
        self._ensure_unlocked()

        fmt = args.format or detect_format(args.file)
        result = import_file(args.file, fmt)

        if result.success_count > 0:
            for entry in result.imported:
                self.vault.add_entry(entry)
            self.vault.save()
            self._success(f"成功导入 {result.success_count} 个条目")
        else:
            self._error("导入失败，没有导入任何条目")

        if result.errors and not self.json_output:
            for error in result.errors:
                print(f"  错误: {error}")

        if self.json_output:
            print(json.dumps({
                "success_count": result.success_count,
                "skip_count": result.skip_count,
                "error_count": result.error_count,
                "format": result.format_detected,
                "errors": result.errors,
            }, ensure_ascii=False))

    def _cmd_export(self, args):
        """export 命令"""
        self._ensure_unlocked()

        entries = self.vault.list_entries()
        password = args.password

        if args.encrypted and not password:
            try:
                password = getpass.getpass("请输入导出密码: ")
            except (EOFError, KeyboardInterrupt):
                self._error("已取消")
                return

        if args.format == "json":
            result = export_to_json(entries, args.file, args.encrypted, password)
        else:
            result = export_to_csv(entries, args.file, args.encrypted, password)

        if not args.encrypted and not self.json_output:
            print("警告: 未加密导出包含明文密码，请妥善保管！")

        if self.json_output:
            print(json.dumps(result.to_dict(), ensure_ascii=False))
        else:
            self._success(f"已导出 {result.exported_count} 个条目到 {args.file}")

    def _cmd_stats(self, args):
        """stats 命令"""
        self._ensure_unlocked()
        self._show_stats()

    def _cmd_lock(self, args):
        """lock 命令"""
        self.vault.lock()
        self._success("密码库已锁定")

    def _cmd_change_password(self, args):
        """change-password 命令"""
        self._ensure_unlocked()

        try:
            old_password = getpass.getpass("请输入当前主密码: ")
            new_password1 = getpass.getpass("请输入新主密码: ")
            new_password2 = getpass.getpass("请再次输入新主密码: ")
        except (EOFError, KeyboardInterrupt):
            self._error("已取消")
            return

        if new_password1 != new_password2:
            self._error("两次输入的新密码不一致")
            return

        if len(new_password1) < 6:
            self._error("主密码至少 6 个字符")
            return

        if self.vault.change_master_password(old_password, new_password1):
            self._success("主密码修改成功")
        else:
            self._error("修改失败，请检查当前密码是否正确")

    def _cmd_totp(self, args):
        """totp 命令"""
        self._ensure_unlocked()

        if not args.id:
            self._error("请指定条目 ID 或标题")
            return

        entry = self._find_entry(args.id)
        if not entry:
            self._error(f"未找到条目: {args.id}")
            return

        if args.add:
            if not args.secret:
                self._error("请提供 --secret 参数")
                return

            entry.totp.secret = args.secret
            entry.totp.issuer = args.issuer or ""
            recovery_codes = TOTPGenerator(args.secret).generate_recovery_codes()
            entry.totp.recovery_codes = recovery_codes

            self.vault.update_entry(entry)
            self.vault.save()

            if self.json_output:
                print(json.dumps({
                    "status": "added",
                    "recovery_codes": recovery_codes,
                }, ensure_ascii=False))
            else:
                self._success("TOTP 已添加")
                print("备用恢复码（请妥善保存）:")
                for code in recovery_codes:
                    print(f"  {code}")
            return

        if not entry.totp.is_enabled:
            self._error("该条目未启用 TOTP")
            return

        totp_gen = TOTPGenerator(
            secret=entry.totp.secret,
            digits=entry.totp.digits,
            period=entry.totp.period,
            issuer=entry.totp.issuer,
        )

        code = totp_gen.generate_code()
        remaining = totp_gen.time_remaining()

        if args.clip:
            if copy_to_clipboard(code, self.clipboard_clear_delay):
                if not self.json_output:
                    self._success(f"验证码已复制到剪贴板，{self.clipboard_clear_delay} 秒后自动清除")
            else:
                self._error("无法复制到剪贴板")
            return

        if self.json_output:
            print(json.dumps({
                "code": code,
                "remaining": remaining,
                "period": entry.totp.period,
            }, ensure_ascii=False))
        else:
            print(f"验证码: {format_code(code)}")
            print(f"剩余时间: {remaining}s")

    def _ensure_unlocked(self):
        """确保密码库已解锁"""
        if self.vault.is_locked:
            if not self.vault.exists():
                self._error("密码库不存在，请先使用 init 命令创建")
                sys.exit(1)

            if self.locker.is_locked:
                self._error(self.locker.get_status_message())
                sys.exit(1)

            try:
                password = getpass.getpass("请输入主密码: ")
            except (EOFError, KeyboardInterrupt):
                self._error("已取消")
                sys.exit(1)

            if self.vault.unlock(password):
                self.locker.record_success()
            else:
                self.locker.record_failure()
                if self.locker.is_locked:
                    self._error(self.locker.get_status_message())
                else:
                    self._error(f"密码错误，{self.locker.get_status_message()}")
                sys.exit(1)

    def _success(self, msg: str):
        """输出成功消息"""
        if self.json_output:
            print(json.dumps({"status": "success", "message": msg}))
        else:
            print(f"✓ {msg}")

    def _error(self, msg: str):
        """输出错误消息并退出"""
        if self.json_output:
            print(json.dumps({"status": "error", "message": msg}))
        else:
            print(f"✗ {msg}", file=sys.stderr)
        sys.exit(1)

    def _message(self, msg: str):
        """输出普通消息"""
        if self.json_output:
            print(json.dumps({"status": "info", "message": msg}))
        else:
            print(msg)

    def _warning(self, msg: str):
        """输出警告消息"""
        if self.json_output:
            print(json.dumps({"status": "warning", "message": msg}))
        else:
            print(f"⚠ {msg}")

    def _print_success(self, msg: str):
        """打印成功消息（不退出）"""
        if self.json_output:
            print(json.dumps({"status": "success", "message": msg}))
        else:
            print(f"✓ {msg}")

    def _print_error(self, msg: str):
        """打印错误消息（不退出）"""
        if self.json_output:
            print(json.dumps({"status": "error", "message": msg}))
        else:
            print(f"✗ {msg}")

    def _print_message(self, msg: str):
        """打印普通消息"""
        print(msg)

    def _print_warning(self, msg: str):
        """打印警告消息"""
        if self.json_output:
            print(json.dumps({"status": "warning", "message": msg}))
        else:
            print(f"⚠ {msg}")


def main():
    """主函数"""
    cli = PasswordManagerCLI()
    cli.run()


if __name__ == "__main__":
    main()
