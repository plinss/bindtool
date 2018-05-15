from setuptools import setup

setup(
    name="bindtool",
    version="1.0",
    scripts=["bindtool.py"],
    install_requires=["py3dns>=3.1.0"],
    entry_points={
        "console_scripts": [
            "bindtool = bindtool:BindTool.Run"
        ]
    }
)