"""Compatibility entry point for the executable notebook validation suite."""

from pathlib import Path
import runpy


runpy.run_path(Path(__file__).with_name("execute-notebooks.py"), run_name="__main__")
