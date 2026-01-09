from patcher.dl.features import FEATURE_NAMES, extract_features
from patcher.ranker import Candidate


def test_patch_ranker_feature_vector_stable() -> None:
    candidate = Candidate(
        candidate_id="det-0",
        diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-print('x')\n+print('y')\n",
        source="deterministic",
        diff_ok=True,
        validated=True,
        validation_status="validated",
    )
    features1 = extract_features(candidate)
    features2 = extract_features(candidate)
    assert features1.values == features2.values
    assert len(features1.values) == len(FEATURE_NAMES)
