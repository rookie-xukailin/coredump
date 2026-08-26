# -*- coding: utf-8 -*-
"""bmccore - BMC coredump 离线分析工具包。

唯一第三方依赖 pyelftools 以 vendoring 方式放在仓库 open/pyelftools 下，
这里在导入时把该目录加入 sys.path（若环境里没有已安装版本）。
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_OPEN_PYELFTOOLS = os.path.join(_ROOT, "open", "pyelftools")

try:
    import elftools  # noqa: F401
except ImportError:
    if os.path.isdir(_OPEN_PYELFTOOLS):
        sys.path.insert(0, _OPEN_PYELFTOOLS)
        import elftools  # noqa: F401

__version__ = "0.1.0"
