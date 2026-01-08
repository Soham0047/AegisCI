import torch

from ml.ensemble import detect_ood, fit_embedding_stats, mahalanobis_distance


def test_ood_distance_trigger():
    embeddings = torch.tensor([[0.0, 0.0], [0.1, -0.1], [-0.1, 0.1]])
    stats = fit_embedding_stats(embeddings)
    far = torch.tensor([10.0, 10.0])
    distance = mahalanobis_distance(far, stats)
    flag, reason = detect_ood(
        entropy_value=0.0,
        entropy_threshold=1.0,
        distance_value=distance,
        distance_threshold=5.0,
    )
    assert flag is True
    assert reason == "embedding_distance"
