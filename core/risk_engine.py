# core/risk_engine.py
from dataclasses import dataclass

@dataclass
class RiskResult:
    score: float
    level: str
    threats: list

class RiskEngine:
    def calculate(self, threat_codes):
        # Упрощенная логика расчета
        threat_levels = {
            "УБПД.01": 0.7,
            "УБПД.07": 1.0
        }
        
        score = sum(threat_levels.get(code, 0) for code in threat_codes)
        
        if score >= 1.0:
            level = "Критический"
        elif score >= 0.5:
            level = "Высокий"
        else:
            level = "Средний"
        
        return RiskResult(
            score=score,
            level=level,
            threats=[{"code": code} for code in threat_codes]
        )