from core.scoring import risk_level_for_score


def test_risk_level_thresholds():
    assert risk_level_for_score(0) == "LOW"
    assert risk_level_for_score(5) == "MEDIUM"
    assert risk_level_for_score(9) == "HIGH"
    assert risk_level_for_score(15) == "CRITICAL"
