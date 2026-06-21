#!/usr/bin/env python3
"""密码管理器 - 主入口脚本"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwmgr.cli import main

if __name__ == "__main__":
    main()
