import torch

from ml.train_transformer import fit_temperature


def test_temperature_scaling_changes_value():
    logits = torch.tensor([0.1, 1.2, -0.7, 0.3])
    labels = torch.tensor([0.0, 1.0, 0.0, 1.0])
    temperature = fit_temperature(logits, labels)
    assert temperature > 0.0
