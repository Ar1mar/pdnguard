import nmap
import requests
import socket
from urllib.parse import urlparse
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable

class ScannerSignals(QObject):
    progress = pyqtSignal(str)
    result = pyqtSignal(dict)
    finished = pyqtSignal()

class Scanner(QRunnable):
    def __init__(self, target):
        super().__init__()
        self.target = target
        self.signals = ScannerSignals()
        self._is_running = True

    def run(self):
        try:
            result = {'target': self.target}
            
            # 1. Разрешение доменного имени
            ip = self._resolve_domain()
            if not ip:
                raise ValueError("Не удалось разрешить доменное имя")
            
            # 2. Сканирование портов
            scan_result = self._scan_ports(ip)
            result.update(scan_result)
            
            # 3. Проверка веб-уязвимостей
            if self._has_web_ports(scan_result):
                web_result = self._scan_web()
                result.update(web_result)
            
            self.signals.result.emit(result)
            
        except Exception as e:
            self.signals.result.emit({'error': str(e)})
        finally:
            self.signals.finished.emit()

    def _resolve_domain(self):
        try:
            domain = urlparse(self.target).netloc or self.target
            return socket.gethostbyname(domain.split(':')[0])
        except socket.gaierror:
            return None

    def _scan_ports(self, ip):
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-T4 -F --open --host-timeout 5m')
            
            return {
                'ip': ip,
                'open_ports': list(nm[ip]['tcp'].keys()),
                'services': {
                    port: nm[ip]['tcp'][port]['name']
                    for port in nm[ip]['tcp']
                }
            }
        except Exception as e:
            raise Exception(f"Ошибка сканирования: {str(e)}")

    def _has_web_ports(self, scan_data):
        return any(port in [80, 443, 8080, 8443] for port in scan_data.get('open_ports', []))

    def _scan_web(self):
        vulns = []
        try:
            url = f"http://{self.target}" if not self.target.startswith('http') else self.target
            response = requests.get(url, timeout=10, verify=False)
            
            # Проверка security headers
            headers_to_check = [
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]
            
            for header in headers_to_check:
                if header not in response.headers:
                    vulns.append(f"Отсутствует заголовок: {header}")
            
            # Проверка на SQL-инъекции
            test_url = f"{url}/?id=1'"
            test_response = requests.get(test_url, timeout=5, verify=False)
            if "error" in test_response.text.lower():
                vulns.append("Возможна SQL-инъекция")
                
        except Exception as e:
            vulns.append(f"Ошибка веб-проверки: {str(e)}")
        
        return {'web_vulnerabilities': vulns}

    def stop(self):
        self._is_running = False