import shutil
import os
import subprocess
from datetime import datetime
from typing import List, Optional
import asyncio
import time


def get_nmap_path() -> str:
    """Find Nmap executable on the system."""
    if shutil.which("nmap"):
        return "nmap"

    default_paths = [r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe"]

    for path in default_paths:
        if os.path.exists(path):
            return path

    return ""

