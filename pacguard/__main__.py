"""
Pacguard CLI package runner for 'python3 -m pacguard'.
"""

import sys
from pacguard.cli import main

if __name__ == "__main__":
    sys.exit(main())
