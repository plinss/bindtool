"""BindTool module."""

import sys

from .bindtool import BindTool, BindToolError

__all__ = ['BindTool', 'BindToolError']


def run() -> int:
    tool = None
    try:
        tool = BindTool()
        tool.run()
    except BindToolError:
        return 1
    if (tool):
        try:
            del tool
        except Exception:
            pass
    return 0


if __name__ == '__main__':      # called from the command line
    sys.exit(run())
