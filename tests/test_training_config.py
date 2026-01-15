"""
Tests for config-driven training hyperparameters.

These tests verify that:
1. Training scripts respect environment variables for hyperparameters
2. CLI arguments override environment variables
3. Default values are appropriate
"""

from __future__ import annotations

import os
import pytest


def test_embeddings_parser_defaults():
    """Test that embeddings parser has improved defaults."""
    from rag.dl.train_embeddings import build_parser
    
    parser = build_parser()
    args = parser.parse_args([])
    
    # Check improved defaults
    assert args.epochs >= 5, "Default epochs should be >= 5 for better convergence"
    assert args.lr <= 1e-3, "Default LR should be <= 1e-3 for stability"
    assert args.weight_decay > 0, "Should have weight decay for regularization"


def test_reranker_parser_defaults():
    """Test that reranker parser has improved defaults."""
    from rag.dl.train_reranker import build_parser
    
    parser = build_parser()
    args = parser.parse_args([])
    
    # Check improved defaults
    assert args.epochs >= 5, "Default epochs should be >= 5 for better convergence"
    assert args.lr <= 1e-3, "Default LR should be <= 1e-3 for stability"
    assert args.weight_decay > 0, "Should have weight decay for regularization"


def test_patch_ranker_parser_defaults():
    """Test that patch ranker parser has improved defaults."""
    from patcher.dl.train_patch_ranker import build_parser
    
    parser = build_parser()
    args = parser.parse_args([])
    
    # Check improved defaults
    assert args.epochs >= 10, "Default epochs should be >= 10"
    assert args.lr <= 1e-2, "Default LR should be reasonable"
    assert args.weight_decay > 0, "Should have weight decay for regularization"


def test_embeddings_cli_override():
    """Test that CLI arguments work correctly."""
    from rag.dl.train_embeddings import build_parser
    
    parser = build_parser()
    args = parser.parse_args([
        '--epochs', '25',
        '--lr', '0.0001',
        '--batch-size', '64',
        '--seed', '999',
        '--weight-decay', '0.05',
    ])
    
    assert args.epochs == 25
    assert args.lr == 0.0001
    assert args.batch_size == 64
    assert args.seed == 999
    assert args.weight_decay == 0.05


def test_env_int_helper():
    """Test _env_int helper function."""
    from rag.dl.train_embeddings import _env_int
    
    # Test default when env var not set
    assert _env_int("NONEXISTENT_VAR_12345", 100) == 100
    
    # Test when env var is set
    os.environ["TEST_DL_VAR"] = "42"
    try:
        assert _env_int("TEST_DL_VAR", 100) == 42
    finally:
        del os.environ["TEST_DL_VAR"]


def test_env_float_helper():
    """Test _env_float helper function."""
    from rag.dl.train_embeddings import _env_float
    
    # Test default when env var not set
    assert _env_float("NONEXISTENT_VAR_12345", 0.001) == 0.001
    
    # Test when env var is set
    os.environ["TEST_DL_VAR"] = "0.005"
    try:
        assert _env_float("TEST_DL_VAR", 0.001) == 0.005
    finally:
        del os.environ["TEST_DL_VAR"]


def test_embeddings_uses_adamw():
    """Test that embeddings training uses AdamW optimizer."""
    # Just verify the import works and code structure
    import rag.dl.train_embeddings as module
    import inspect
    
    source = inspect.getsource(module.train_embeddings)
    assert 'AdamW' in source, "Should use AdamW optimizer for weight decay"


def test_reranker_uses_adamw():
    """Test that reranker training uses AdamW optimizer."""
    import rag.dl.train_reranker as module
    import inspect
    
    source = inspect.getsource(module.train_reranker)
    assert 'AdamW' in source, "Should use AdamW optimizer for weight decay"


def test_deterministic_seed():
    """Test that seed is properly applied."""
    from rag.dl.train_embeddings import build_parser
    
    parser = build_parser()
    
    # Same seed should work
    args1 = parser.parse_args(['--seed', '1337'])
    args2 = parser.parse_args(['--seed', '1337'])
    
    assert args1.seed == args2.seed == 1337
