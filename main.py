import os
os.environ['PATH'] += r';C:\Program Files\wkhtmltopdf\bin'
import sys
from PyQt6.QtWidgets import QApplication
from core.database import init_db
from gui.main_window import MainWindow
import urllib3

# Отключение предупреждений SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    init_db()  # Инициализация БД
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()