from PyQt5.QtWidgets import QApplication
from ui.main_window import SM2Tool
import sys

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = SM2Tool()
    win.show()
    sys.exit(app.exec_())