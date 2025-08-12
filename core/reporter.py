# core/reporter.py
import os
import pdfkit
from datetime import datetime
from jinja2 import Template

class Reporter:
    def __init__(self):
        self.reports_dir = "reports"
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Шаблон отчета
        self.template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Отчет безопасности ПДн</title>
            <style>
                body { font-family: Arial; margin: 20px; }
                .critical { color: red; }
                .high { color: orange; }
                .medium { color: #FFCC00; }
                table { width: 100%; border-collapse: collapse; }
                th, td { border: 1px solid #ddd; padding: 8px; }
            </style>
        </head>
        <body>
            <h1>Отчет оценки безопасности ПДн</h1>
            <p>Дата: {{date}}</p>
            <p>Цель: {{target}}</p>
            <p>IP-адрес: {{ip}}</p>
            
            <h2>Результаты оценки</h2>
            <p>Уровень риска: <span class="{{risk_level}}">{{risk_level}}</span></p>
            <p>Общий балл: {{score}}/5.0</p>
            
            <h3>Найденные угрозы</h3>
            <table>
                <tr><th>Код</th><th>Описание</th><th>Уровень</th></tr>
                {% for threat in threats %}
                <tr>
                    <td>{{threat.code}}</td>
                    <td>{{threat.description}}</td>
                    <td class="{{threat.level}}">{{threat.level}}</td>
                </tr>
                {% endfor %}
            </table>
            
            {% if vulnerabilities %}
            <h3>Веб-уязвимости</h3>
            <ul>
                {% for vuln in vulnerabilities %}
                <li>{{vuln}}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </body>
        </html>
        """

    def generate_pdf(self, data):
        """Генерация PDF отчета"""
        try:
            # Создаем безопасное имя файла
            safe_name = "".join(c if c.isalnum() else "_" for c in data['target'])
            filename = os.path.join(self.reports_dir, f"report_{safe_name}.pdf")
            
            # Подготовка данных
            html = Template(self.template).render(
                date=datetime.now().strftime("%d.%m.%Y %H:%M"),
                target=data['target'],
                ip=data.get('ip', 'не определен'),
                score=data['score'],
                risk_level=data['level'].lower(),
                threats=data['threats'],
                vulnerabilities=data.get('vulnerabilities', [])
            )
            
            # Генерация PDF
            options = {
                'encoding': 'UTF-8',
                'quiet': '',
                'enable-local-file-access': None
            }
            pdfkit.from_string(html, filename, options=options)
            
            return os.path.abspath(filename)
        except Exception as e:
            print(f"Ошибка генерации отчета: {str(e)}")
            return None