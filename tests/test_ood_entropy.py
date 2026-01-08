import torch

from ml.ensemble import compute_entropy, detect_ood


def test_ood_entropy_trigger():
    probs = torch.tensor([0.5, 0.5])
    entropy = float(compute_entropy(probs.unsqueeze(0)).item())
    flag, reason = detect_ood(
        entropy, entropy_threshold=0.1, distance_value=None, distance_threshold=None
    )
    assert flag is True
    assert reason == "entropy"
