"""剪贴板管理模块 - 复制后自动清除"""

import time
import threading
from typing import Optional

try:
    import pyperclip
    HAS_PYPERCLIP = True
except ImportError:
    HAS_PYPERCLIP = False


class ClipboardManager:
    """剪贴板管理器，支持定时自动清除"""

    DEFAULT_CLEAR_DELAY = 5

    def __init__(self, clear_delay: int = 5):
        self.clear_delay = clear_delay
        self._clear_timer: Optional[threading.Timer] = None
        self._last_copied_text: str = ""
        self._lock = threading.Lock()

    def copy(self, text: str, clear_after: Optional[int] = None) -> bool:
        """复制文本到剪贴板，并在指定时间后自动清除

        Args:
            text: 要复制的文本
            clear_after: 自动清除时间（秒），默认使用 clear_delay

        Returns:
            是否复制成功
        """
        if not HAS_PYPERCLIP:
            return False

        with self._lock:
            self._cancel_clear_timer()
            try:
                pyperclip.copy(text)
                self._last_copied_text = text

                delay = clear_after if clear_after is not None else self.clear_delay
                if delay > 0:
                    self._clear_timer = threading.Timer(delay, self._auto_clear)
                    self._clear_timer.daemon = True
                    self._clear_timer.start()
                return True
            except Exception:
                return False

    def paste(self) -> str:
        """从剪贴板获取文本"""
        if not HAS_PYPERCLIP:
            return ""
        try:
            return pyperclip.paste()
        except Exception:
            return ""

    def clear(self):
        """立即清除剪贴板"""
        with self._lock:
            self._cancel_clear_timer()
            if HAS_PYPERCLIP:
                try:
                    pyperclip.copy("")
                except Exception:
                    pass
            self._last_copied_text = ""

    def _auto_clear(self):
        """自动清除剪贴板（仅当内容与上次复制的相同时才清除）"""
        with self._lock:
            if HAS_PYPERCLIP and self._last_copied_text:
                try:
                    current = pyperclip.paste()
                    if current == self._last_copied_text:
                        pyperclip.copy("")
                except Exception:
                    pass
                self._last_copied_text = ""

    def _cancel_clear_timer(self):
        """取消清除定时器"""
        if self._clear_timer is not None:
            try:
                self._clear_timer.cancel()
            except Exception:
                pass
            self._clear_timer = None

    @property
    def is_available(self) -> bool:
        """检查剪贴板是否可用"""
        return HAS_PYPERCLIP

    @property
    def remaining_time(self) -> float:
        """获取距离自动清除的剩余时间（秒）"""
        if self._clear_timer is None or not self._clear_timer.is_alive():
            return 0.0
        return self._clear_timer.interval - (time.time() - self._clear_timer.started_at if hasattr(self._clear_timer, 'started_at') else 0)

    def __del__(self):
        """析构时清除定时器"""
        self._cancel_clear_timer()


_default_manager: Optional[ClipboardManager] = None


def get_clipboard_manager() -> ClipboardManager:
    """获取默认剪贴板管理器单例"""
    global _default_manager
    if _default_manager is None:
        _default_manager = ClipboardManager()
    return _default_manager


def copy_to_clipboard(text: str, clear_after: int = 5) -> bool:
    """便捷函数：复制到剪贴板并自动清除"""
    manager = get_clipboard_manager()
    return manager.copy(text, clear_after)


def clear_clipboard():
    """便捷函数：清除剪贴板"""
    manager = get_clipboard_manager()
    manager.clear()
