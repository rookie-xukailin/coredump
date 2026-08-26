#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bmc-core CLI 入口（实现在 bmccore/cli.py）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bmccore.cli import main

if __name__ == "__main__":
    sys.exit(main())
