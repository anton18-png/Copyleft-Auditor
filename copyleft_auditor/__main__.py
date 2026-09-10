"""Entry point: python -m copyleft_auditor"""

import os
import sys

_package_dir = os.path.dirname(os.path.abspath(__file__))
_project_dir = os.path.dirname(_package_dir)
if _project_dir not in sys.path:
    sys.path.insert(0, _project_dir)

from copyleft_auditor.gui.app import CopyleftAuditorApp


def main():
    app = CopyleftAuditorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
