"""锁定机制模块 - 失败计数、定时锁定"""

import json
import time
import os
from pathlib import Path
from typing import Optional


class LockManager:
    """锁定管理器

    管理密码尝试失败计数和锁定状态
    输错 3 次锁定 5 分钟
    """

    DEFAULT_MAX_ATTEMPTS = 3
    DEFAULT_LOCK_DURATION = 300  # 5 分钟（秒）

    def __init__(
        self,
        state_file: str,
        max_attempts: int = 3,
        lock_duration: int = 300,
    ):
        self.state_file = Path(state_file)
        self.max_attempts = max_attempts
        self.lock_duration = lock_duration
        self._failed_attempts: int = 0
        self._lock_until: float = 0
        self._load_state()

    @property
    def is_locked(self) -> bool:
        """检查当前是否处于锁定状态"""
        if self._lock_until == 0:
            return False
        return time.time() < self._lock_until

    @property
    def remaining_lock_time(self) -> int:
        """获取剩余锁定时间（秒）"""
        if not self.is_locked:
            return 0
        return int(self._lock_until - time.time())

    @property
    def failed_attempts(self) -> int:
        """获取失败尝试次数"""
        return self._failed_attempts

    @property
    def remaining_attempts(self) -> int:
        """获取剩余尝试次数"""
        if self.is_locked:
            return 0
        return max(0, self.max_attempts - self._failed_attempts)

    def record_failure(self):
        """记录一次失败尝试"""
        self._failed_attempts += 1
        if self._failed_attempts >= self.max_attempts:
            self._lock_until = time.time() + self.lock_duration
            self._failed_attempts = 0
        self._save_state()

    def record_success(self):
        """记录成功，重置计数"""
        self._failed_attempts = 0
        self._lock_until = 0
        self._save_state()

    def reset(self):
        """重置所有状态"""
        self._failed_attempts = 0
        self._lock_until = 0
        self._save_state()

    def _load_state(self):
        """从文件加载状态"""
        if not self.state_file.exists():
            return

        try:
            with open(self.state_file, "r") as f:
                data = json.load(f)

            self._failed_attempts = data.get("failed_attempts", 0)
            self._lock_until = data.get("lock_until", 0)

            if self._lock_until and time.time() >= self._lock_until:
                self._lock_until = 0
                self._failed_attempts = 0
                self._save_state()
        except (json.JSONDecodeError, IOError):
            self._failed_attempts = 0
            self._lock_until = 0

    def _save_state(self):
        """保存状态到文件"""
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "failed_attempts": self._failed_attempts,
                "lock_until": self._lock_until,
            }
            with open(self.state_file, "w") as f:
                json.dump(data, f)
        except IOError:
            pass

    def get_status_message(self) -> str:
        """获取状态描述消息"""
        if self.is_locked:
            remaining = self.remaining_lock_time
            minutes = remaining // 60
            seconds = remaining % 60
            if minutes > 0:
                return f"账户已锁定，请在 {minutes} 分 {seconds} 秒后再试"
            else:
                return f"账户已锁定，请在 {seconds} 秒后再试"
        else:
            remaining = self.remaining_attempts
            return f"剩余尝试次数: {remaining}"

    def clear_state_file(self):
        """清除状态文件"""
        if self.state_file.exists():
            try:
                os.remove(self.state_file)
            except OSError:
                pass
        self._failed_attempts = 0
        self._lock_until = 0
