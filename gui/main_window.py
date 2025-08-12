# gui/main_window.py
from PyQt6.QtWidgets import (QMainWindow, QVBoxLayout, QWidget, 
                            QPushButton, QLabel, QLineEdit,
                            QTextEdit, QProgressBar, QMessageBox)
from PyQt6.QtCore import Qt, QThreadPool
from core.scanner import Scanner
from core.risk_engine import RiskEngine
from core.reporter import Reporter
import os

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PDnGuard - Оценка безопасности ПДн")
        self.resize(900, 700)
        self.threadpool = QThreadPool()
        self._setup_ui()

    def _setup_ui(self):
        central_widget = QWidget()
        layout = QVBoxLayout()
        
        # Элементы интерфейса
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com или 192.168.1.1")
        
        self.scan_btn = QPushButton("Начать сканирование")
        self.scan_btn.clicked.connect(self._start_scan)
        
        self.stop_btn = QPushButton("Остановить")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        
        # Компоновка
        layout.addWidget(QLabel("Цель сканирования:"))
        layout.addWidget(self.target_input)
        layout.addWidget(self.scan_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.log_output)
        
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)

    def _start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Ошибка", "Введите домен или IP-адрес")
            return
        
        self._reset_ui()
        self.log_output.append(f"Начато сканирование: {target}")
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        
        scanner = Scanner(target)
        scanner.signals.progress.connect(self._update_progress)
        scanner.signals.result.connect(self._process_results)
        scanner.signals.finished.connect(self._scan_finished)
        self.threadpool.start(scanner)

    def _stop_scan(self):
        self.threadpool.clear()
        self.log_output.append("Сканирование остановлено")
        self._reset_ui()

    def _update_progress(self, message):
        self.log_output.append(f"> {message}")
        self.progress_bar.setValue(self.progress_bar.value() + 10)

    def _process_results(self, results):
        if 'error' in results:
            self.log_output.append(f"\nОшибка: {results['error']}")
            return
        
        # Анализ рисков
        threats = self._detect_threats(results)
        risk_result = RiskEngine().calculate(threats)
        
        # Генерация отчета
        reporter = Reporter()
        report_data = {
            'target': self.target_input.text(),
            'ip': results.get('ip', ''),
            'score': risk_result.score,
            'level': risk_result.level,
            'threats': risk_result.threats,
            'vulnerabilities': results.get('web_vulnerabilities', [])
        }
        
        report_path = reporter.generate_pdf(report_data)
        
        if report_path:
            self.log_output.append(f"\nОтчет сохранен: {report_path}")
        else:
            self.log_output.append("\nНе удалось создать отчет")

    def _detect_threats(self, scan_data):
        threats = []
        if 'web_vulnerabilities' in scan_data:
            if any("SQL" in vuln for vuln in scan_data['web_vulnerabilities']):
                threats.append("УБПД.07")
        return threats if threats else ["УБПД.01"]

    def _scan_finished(self):
        self.progress_bar.setValue(100)
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _reset_ui(self):
        self.progress_bar.setValue(0)
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)