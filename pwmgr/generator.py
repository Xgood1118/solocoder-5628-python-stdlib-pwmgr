"""密码生成器和强度评估"""

import secrets
import string
import math
from typing import Set, Tuple, Dict, Any


CHARSETS = {
    "lowercase": string.ascii_lowercase,
    "uppercase": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?",
    "ambiguous": "il1Lo0O",
}

DEFAULT_SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

AMBIGUOUS_CHARS = "il1Lo0O"


class PasswordGenerator:
    """密码生成器"""

    def __init__(
        self,
        length: int = 16,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = False,
        custom_symbols: str = "",
    ):
        self.length = length
        self.use_lowercase = use_lowercase
        self.use_uppercase = use_uppercase
        self.use_digits = use_digits
        self.use_symbols = use_symbols
        self.exclude_ambiguous = exclude_ambiguous
        self.custom_symbols = custom_symbols or DEFAULT_SYMBOLS

    def _get_charset(self) -> str:
        """获取字符集"""
        charset = ""
        if self.use_lowercase:
            charset += string.ascii_lowercase
        if self.use_uppercase:
            charset += string.ascii_uppercase
        if self.use_digits:
            charset += string.digits
        if self.use_symbols:
            charset += self.custom_symbols

        if self.exclude_ambiguous:
            charset = "".join(c for c in charset if c not in AMBIGUOUS_CHARS)

        if not charset:
            raise ValueError("至少需要选择一种字符类型")

        return charset

    def generate(self, length: int = None) -> str:
        """生成密码

        确保每种选中的字符类型至少出现一次
        """
        if length is None:
            length = self.length

        if length < 4:
            raise ValueError("密码长度至少为 4 个字符")

        charset = self._get_charset()
        required = []

        if self.use_lowercase:
            lowercase_chars = "".join(c for c in string.ascii_lowercase if c in charset)
            if lowercase_chars:
                required.append(secrets.choice(lowercase_chars))
        if self.use_uppercase:
            uppercase_chars = "".join(c for c in string.ascii_uppercase if c in charset)
            if uppercase_chars:
                required.append(secrets.choice(uppercase_chars))
        if self.use_digits:
            digit_chars = "".join(c for c in string.digits if c in charset)
            if digit_chars:
                required.append(secrets.choice(digit_chars))
        if self.use_symbols:
            symbol_chars = "".join(c for c in self.custom_symbols if c in charset)
            if symbol_chars:
                required.append(secrets.choice(symbol_chars))

        remaining_length = length - len(required)
        if remaining_length < 0:
            remaining_length = 0

        password_chars = required.copy()
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(charset))

        password_list = list(password_chars)
        for i in range(len(password_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_list[i], password_list[j] = password_list[j], password_list[i]

        return "".join(password_list)

    def generate_multiple(self, count: int, length: int = None) -> list:
        """生成多个密码"""
        return [self.generate(length) for _ in range(count)]

    def get_entropy(self, length: int = None) -> float:
        """计算密码熵（比特）"""
        if length is None:
            length = self.length
        charset_size = len(self._get_charset())
        if charset_size <= 1:
            return 0.0
        return length * math.log2(charset_size)

    @staticmethod
    def generate_pin(length: int = 6) -> str:
        """生成 PIN 码（纯数字）"""
        return "".join(secrets.choice(string.digits) for _ in range(length))

    @staticmethod
    def generate_passphrase(num_words: int = 4, separator: str = "-") -> str:
        """生成易记密码短语"""
        words = [
            "apple", "banana", "cherry", "dragon", "eagle", "forest",
            "garden", "harbor", "island", "jungle", "kingdom", "lemon",
            "mountain", "night", "ocean", "panda", "queen", "river",
            "sunset", "tiger", "umbrella", "valley", "willow", "xenon",
            "yellow", "zebra", "alpha", "beta", "gamma", "delta",
            "crystal", "diamond", "emerald", "falcon", "galaxy", "horizon",
            "ivory", "jupiter", "kraken", "lunar", "mercury", "nebula",
            "omega", "phoenix", "quantum", "rocket", "saturn", "thunder",
        ]
        selected = [secrets.choice(words) for _ in range(num_words)]
        return separator.join(selected)


class PasswordStrength:
    """密码强度评估结果"""

    def __init__(self, score: int, level: str, feedback: list):
        self.score = score
        self.level = level
        self.feedback = feedback

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "feedback": self.feedback,
        }


def evaluate_password_strength(password: str) -> PasswordStrength:
    """评估密码强度（自实现评分系统）

    评分范围: 0-100
    等级: very_weak, weak, medium, strong, very_strong
    """
    score = 0
    feedback = []

    if not password:
        return PasswordStrength(0, "very_weak", ["密码不能为空"])

    length = len(password)

    if length < 6:
        feedback.append("密码太短，容易被暴力破解")
    elif length < 8:
        score += 10
        feedback.append("建议密码长度至少 8 位")
    elif length < 12:
        score += 25
    elif length < 16:
        score += 35
    elif length < 20:
        score += 45
    else:
        score += 50

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    if has_lower:
        score += 10
    else:
        feedback.append("建议添加小写字母")

    if has_upper:
        score += 10
    else:
        feedback.append("建议添加大写字母")

    if has_digit:
        score += 10
    else:
        feedback.append("建议添加数字")

    if has_symbol:
        score += 15
    else:
        feedback.append("建议添加特殊符号")

    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_symbol:
        charset_size += 32

    if charset_size > 0:
        entropy = length * math.log2(charset_size)
        if entropy >= 128:
            score += 15
        elif entropy >= 80:
            score += 10
        elif entropy >= 60:
            score += 5
    else:
        score = 0

    common_patterns = [
        "123456", "password", "qwerty", "abc123", "111111",
        "123456789", "12345678", "12345", "iloveyou", "admin",
        "letmein", "welcome", "monkey", "dragon", "master",
        "login", "princess", "sunshine", "shadow", "football",
    ]
    password_lower = password.lower()
    for pattern in common_patterns:
        if pattern in password_lower:
            score -= 30
            feedback.append(f"包含常见模式: {pattern}")
            break

    repeated_chars = 0
    for i in range(len(password) - 2):
        if password[i] == password[i + 1] == password[i + 2]:
            repeated_chars += 1
    if repeated_chars > 0:
        score -= repeated_chars * 5
        feedback.append("包含重复字符序列")

    sequential = 0
    for i in range(len(password) - 2):
        if (password[i + 1] == chr(ord(password[i]) + 1) and
            password[i + 2] == chr(ord(password[i]) + 2)):
            sequential += 1
        if (password[i + 1] == chr(ord(password[i]) - 1) and
            password[i + 2] == chr(ord(password[i]) - 2)):
            sequential += 1
    if sequential > 0:
        score -= sequential * 5
        feedback.append("包含连续字符序列")

    unique_chars = len(set(password))
    if unique_chars < length * 0.3:
        score -= 10
        feedback.append("字符多样性不足")

    score = max(0, min(100, score))

    if score >= 90:
        level = "very_strong"
    elif score >= 70:
        level = "strong"
    elif score >= 50:
        level = "medium"
    elif score >= 30:
        level = "weak"
    else:
        level = "very_weak"

    if score >= 70:
        feedback.append("密码强度良好")
    elif score >= 50:
        feedback.append("密码强度一般，建议增强")
    else:
        feedback.append("密码强度较弱，请加强")

    return PasswordStrength(score, level, feedback)


def get_strength_color(level: str) -> str:
    """获取强度等级对应的颜色描述"""
    colors = {
        "very_weak": "红色",
        "weak": "橙色",
        "medium": "黄色",
        "strong": "绿色",
        "very_strong": "深绿色",
    }
    return colors.get(level, "灰色")


def get_strength_bar(score: int, width: int = 20) -> str:
    """生成强度进度条"""
    filled = int((score / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    return bar
