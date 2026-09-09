"""Compatibility launcher for the grade-upload microservice mapper."""
from pathlib import Path
import runpy

runpy.run_path(str(Path(__file__).parent / "middleware" / "mapper.py"), run_name="__main__")
