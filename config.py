import os
from pathlib import Path

def configure_environment():
    # Windows-specific configuration
    if os.name == "nt":
        cache_dir = Path(os.environ["LOCALAPPDATA"]) / "ScapyCache"

        # Create the directory if needed
        cache_dir.mkdir(parents=True, exist_ok=True)

        # Configure Scapy's cache location
        os.environ["XDG_CACHE_HOME"] = str(cache_dir)