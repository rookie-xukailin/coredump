# -*- coding: utf-8 -*-
"""统一测试入口：python tests/run_all.py（也可用 pytest tests/）。"""
import importlib
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

MODULES = ["test_corefile", "test_intake", "test_scan_heap", "test_e2e",
           "test_system_matrix", "test_py38_compat"]


def main():
    total = failed = 0
    for mod_name in MODULES:
        mod = importlib.import_module(mod_name)
        tests = [(k, v) for k, v in sorted(vars(mod).items())
                 if k.startswith("test_") and callable(v)]
        for name, fn in tests:
            total += 1
            try:
                fn()
                print("PASS  %s.%s" % (mod_name, name))
            except Exception:
                failed += 1
                print("FAIL  %s.%s" % (mod_name, name))
                traceback.print_exc()
    print("-" * 60)
    print("合计 %d 个测试，%d 失败" % (total, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
