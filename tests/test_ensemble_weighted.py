from ml.ensemble import weighted_average


def test_weighted_average():
    probs = [0.2, 0.8]
    weights = [0.25, 0.75]
    result = weighted_average(probs, weights)
    assert abs(result - 0.65) < 1e-6
