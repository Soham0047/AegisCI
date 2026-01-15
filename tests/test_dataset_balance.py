"""
Tests for dataset balancing functionality.

These tests verify that:
1. Dataset balancing produces 50/50 vuln/safe split
2. Balancing is deterministic given the same seed
3. Train/val/test splits preserve class balance
"""

from __future__ import annotations

import os
import pytest
from typing import Literal

# Skip long-running tests unless explicitly enabled
pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_DL_TRAIN_TESTS", "0") != "1",
    reason="Set RUN_DL_TRAIN_TESTS=1 to run DL training tests",
)


def test_balance_dataset_50_50():
    """Test that balance_dataset produces 50/50 split."""
    from rag.dl.dataset import CodeSample, balance_dataset
    
    # Create imbalanced dataset: 70 vuln, 30 safe
    samples = []
    for i in range(70):
        samples.append(CodeSample(
            sample_id=f"vuln-{i}",
            code=f"vulnerable_code_{i}",
            label="vuln",
            source="test",
            language="python",
            metadata={},
        ))
    for i in range(30):
        samples.append(CodeSample(
            sample_id=f"safe-{i}",
            code=f"safe_code_{i}",
            label="safe",
            source="test",
            language="python",
            metadata={},
        ))
    
    # Balance with default 0.5 ratio
    balanced = balance_dataset(samples, balance_ratio=0.5, seed=42)
    
    vuln_count = sum(1 for s in balanced if s.label == "vuln")
    safe_count = sum(1 for s in balanced if s.label == "safe")
    
    assert vuln_count == safe_count, f"Expected equal counts, got {vuln_count} vuln, {safe_count} safe"
    # Should downsample to minority class size
    assert vuln_count == 30, f"Expected 30 of each, got {vuln_count}"


def test_balance_dataset_deterministic():
    """Test that balancing is deterministic with same seed."""
    from rag.dl.dataset import CodeSample, balance_dataset
    
    samples = []
    for i in range(50):
        samples.append(CodeSample(
            sample_id=f"vuln-{i}",
            code=f"vulnerable_code_{i}",
            label="vuln",
            source="test",
            language="python",
            metadata={},
        ))
    for i in range(50):
        samples.append(CodeSample(
            sample_id=f"safe-{i}",
            code=f"safe_code_{i}",
            label="safe",
            source="test",
            language="python",
            metadata={},
        ))
    
    # Balance twice with same seed
    balanced1 = balance_dataset(samples, seed=1337)
    balanced2 = balance_dataset(samples, seed=1337)
    
    # Should produce identical results
    assert len(balanced1) == len(balanced2)
    for s1, s2 in zip(balanced1, balanced2):
        assert s1.sample_id == s2.sample_id, "Samples should be in same order"


def test_balance_dataset_different_seeds():
    """Test that different seeds produce different results."""
    from rag.dl.dataset import CodeSample, balance_dataset
    
    samples = []
    for i in range(50):
        samples.append(CodeSample(
            sample_id=f"vuln-{i}",
            code=f"vulnerable_code_{i}",
            label="vuln",
            source="test",
            language="python",
            metadata={},
        ))
    for i in range(50):
        samples.append(CodeSample(
            sample_id=f"safe-{i}",
            code=f"safe_code_{i}",
            label="safe",
            source="test",
            language="python",
            metadata={},
        ))
    
    balanced1 = balance_dataset(samples, seed=42)
    balanced2 = balance_dataset(samples, seed=43)
    
    # Should produce different orderings
    ids1 = [s.sample_id for s in balanced1]
    ids2 = [s.sample_id for s in balanced2]
    assert ids1 != ids2, "Different seeds should produce different orderings"


def test_split_dataset_preserves_balance():
    """Test that split_dataset maintains class balance in each split."""
    from rag.dl.dataset import CodeSample, balance_dataset, split_dataset
    
    # Create balanced samples
    samples = []
    for i in range(50):
        samples.append(CodeSample(
            sample_id=f"vuln-{i}",
            code=f"vulnerable_code_{i}",
            label="vuln",
            source="test",
            language="python",
            metadata={},
        ))
    for i in range(50):
        samples.append(CodeSample(
            sample_id=f"safe-{i}",
            code=f"safe_code_{i}",
            label="safe",
            source="test",
            language="python",
            metadata={},
        ))
    
    dataset = split_dataset(samples, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, seed=42)
    
    # Check each split has roughly equal vuln/safe
    for split_name, split_samples in [("train", dataset.train), ("val", dataset.val), ("test", dataset.test)]:
        if len(split_samples) == 0:
            continue
        vuln = sum(1 for s in split_samples if s.label == "vuln")
        safe = sum(1 for s in split_samples if s.label == "safe")
        # Allow small tolerance for rounding
        ratio = vuln / (vuln + safe) if (vuln + safe) > 0 else 0
        assert 0.4 <= ratio <= 0.6, f"{split_name} split has imbalanced ratio: {ratio:.2f}"


def test_split_dataset_deterministic():
    """Test that splitting is deterministic."""
    from rag.dl.dataset import CodeSample, split_dataset
    
    samples = [
        CodeSample(sample_id=f"s-{i}", code=f"code_{i}", label="vuln" if i % 2 == 0 else "safe", source="test", language="python", metadata={})
        for i in range(100)
    ]
    
    ds1 = split_dataset(samples, seed=1337)
    ds2 = split_dataset(samples, seed=1337)
    
    assert [s.sample_id for s in ds1.train] == [s.sample_id for s in ds2.train]
    assert [s.sample_id for s in ds1.val] == [s.sample_id for s in ds2.val]
    assert [s.sample_id for s in ds1.test] == [s.sample_id for s in ds2.test]


def test_oversample_strategy():
    """Test oversampling strategy for minority class."""
    from rag.dl.dataset import CodeSample, balance_dataset
    
    # Create imbalanced: 10 vuln, 90 safe
    samples = []
    for i in range(10):
        samples.append(CodeSample(
            sample_id=f"vuln-{i}",
            code=f"vulnerable_code_{i}",
            label="vuln",
            source="test",
            language="python",
            metadata={},
        ))
    for i in range(90):
        samples.append(CodeSample(
            sample_id=f"safe-{i}",
            code=f"safe_code_{i}",
            label="safe",
            source="test",
            language="python",
            metadata={},
        ))
    
    balanced = balance_dataset(samples, strategy="oversample", seed=42)
    
    vuln_count = sum(1 for s in balanced if s.label == "vuln")
    safe_count = sum(1 for s in balanced if s.label == "safe")
    
    # Oversampling should expand minority to match majority
    assert vuln_count == safe_count == 90


def test_max_samples_per_class():
    """Test max_samples_per_class parameter."""
    from rag.dl.dataset import CodeSample, balance_dataset
    
    samples = []
    for i in range(100):
        samples.append(CodeSample(
            sample_id=f"vuln-{i}",
            code=f"vulnerable_code_{i}",
            label="vuln",
            source="test",
            language="python",
            metadata={},
        ))
    for i in range(100):
        samples.append(CodeSample(
            sample_id=f"safe-{i}",
            code=f"safe_code_{i}",
            label="safe",
            source="test",
            language="python",
            metadata={},
        ))
    
    balanced = balance_dataset(samples, max_samples_per_class=25, seed=42)
    
    vuln_count = sum(1 for s in balanced if s.label == "vuln")
    safe_count = sum(1 for s in balanced if s.label == "safe")
    
    assert vuln_count == 25
    assert safe_count == 25


def test_dataset_stats():
    """Test that dataset stats are computed correctly."""
    from rag.dl.dataset import CodeSample, split_dataset
    
    samples = [
        CodeSample(sample_id=f"s-{i}", code=f"code_{i}", label="vuln" if i % 2 == 0 else "safe", source="test", language="python", metadata={})
        for i in range(100)
    ]
    
    dataset = split_dataset(samples, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1, seed=42)
    
    assert dataset.stats["total_samples"] == 100
    assert dataset.stats["train_size"] == len(dataset.train)
    assert dataset.stats["val_size"] == len(dataset.val)
    assert dataset.stats["test_size"] == len(dataset.test)
    assert dataset.stats["train_vuln"] + dataset.stats["train_safe"] == len(dataset.train)
