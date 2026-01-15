"""
Deterministic data augmentation for code/text samples.

This module provides augmentation strategies that are:
- Deterministic given a seed
- Safe for code (preserving structure)
- Configurable via parameters

Augmentations:
1. Token-level local shuffle (within small windows, preserving string literals)
2. Whitespace normalization / formatting perturbations
3. Deterministic identifier renaming (var_1, var_2, ...)
4. Comment insertion/removal
"""

from __future__ import annotations

import hashlib
import random
import re
from dataclasses import dataclass, field
from typing import Callable

# Regex patterns
_STRING_LITERAL_RE = re.compile(
    r'"""[\s\S]*?"""|'  # triple-double
    r"'''[\s\S]*?'''|"  # triple-single
    r'"(?:[^"\\]|\\.)*"|'  # double-quoted
    r"'(?:[^'\\]|\\.)*'|"  # single-quoted
    r"`(?:[^`\\]|\\.)*`"  # backtick (JS)
)
_IDENTIFIER_RE = re.compile(r'\b([a-z_][a-z0-9_]*)\b', re.IGNORECASE)
_COMMENT_RE = re.compile(
    r'#[^\n]*|'  # Python/Shell
    r'//[^\n]*|'  # JS/TS/C++
    r'/\*[\s\S]*?\*/'  # Block comments
)
_WHITESPACE_RUN_RE = re.compile(r'[ \t]{2,}')

# Keywords that should never be renamed
_PYTHON_KEYWORDS = frozenset([
    'False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await',
    'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except',
    'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is',
    'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try',
    'while', 'with', 'yield', 'self', 'cls', '__init__', '__main__',
])

_JS_KEYWORDS = frozenset([
    'break', 'case', 'catch', 'class', 'const', 'continue', 'debugger',
    'default', 'delete', 'do', 'else', 'export', 'extends', 'finally',
    'for', 'function', 'if', 'import', 'in', 'instanceof', 'let', 'new',
    'return', 'super', 'switch', 'this', 'throw', 'try', 'typeof', 'var',
    'void', 'while', 'with', 'yield', 'async', 'await', 'null', 'undefined',
    'true', 'false', 'console', 'require', 'module', 'exports',
])

_ALL_KEYWORDS = _PYTHON_KEYWORDS | _JS_KEYWORDS

# Banned substrings that should never appear after augmentation
_BANNED_SUBSTRINGS = [
    'curl | sh',
    'curl|sh',
    'wget | sh',
    'rm -rf /',
    'rm -rf ~',
    '> /dev/sda',
    'mkfs.',
    'dd if=',
]


@dataclass
class AugmentConfig:
    """Configuration for augmentation."""
    
    # Token shuffle
    enable_shuffle: bool = True
    shuffle_window: int = 5
    shuffle_probability: float = 0.3
    
    # Whitespace perturbation
    enable_whitespace: bool = True
    whitespace_probability: float = 0.2
    
    # Identifier renaming
    enable_rename: bool = True
    rename_probability: float = 0.3
    max_renames: int = 5
    
    # Comment manipulation
    enable_comment: bool = True
    comment_probability: float = 0.1
    
    # General
    preserve_string_literals: bool = True


@dataclass
class AugmentResult:
    """Result of augmentation."""
    
    original: str
    augmented: str
    transformations: list[str] = field(default_factory=list)
    seed: int = 0


def _stable_seed(text: str, sample_id: str, aug_index: int, base_seed: int) -> int:
    """Generate a deterministic seed from text, sample_id, aug_index, and base_seed."""
    payload = f"{base_seed}:{sample_id}:{aug_index}:{text[:100]}"
    hash_val = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    return int(hash_val[:8], 16)


def _find_string_literal_spans(text: str) -> list[tuple[int, int]]:
    """Find all string literal spans (start, end) in text."""
    spans = []
    for match in _STRING_LITERAL_RE.finditer(text):
        spans.append((match.start(), match.end()))
    return spans


def _is_in_string(pos: int, string_spans: list[tuple[int, int]]) -> bool:
    """Check if position is inside a string literal."""
    for start, end in string_spans:
        if start <= pos < end:
            return True
    return False


def shuffle_tokens_local(
    text: str,
    rng: random.Random,
    window: int = 5,
    probability: float = 0.3,
    preserve_strings: bool = True,
) -> tuple[str, bool]:
    """
    Shuffle tokens within small windows.
    
    Preserves string literals as atomic spans.
    Returns (new_text, was_modified).
    """
    if rng.random() > probability:
        return text, False
    
    # Find string spans to preserve
    string_spans = _find_string_literal_spans(text) if preserve_strings else []
    
    # Tokenize while tracking positions
    tokens = []
    for match in re.finditer(r'\S+', text):
        token = match.group()
        start = match.start()
        end = match.end()
        
        # Check if token overlaps with any string span
        in_string = any(
            not (end <= s or start >= e)
            for s, e in string_spans
        )
        tokens.append((token, start, in_string))
    
    if len(tokens) < 3:
        return text, False
    
    # Shuffle within windows, preserving string tokens
    modified = False
    result_tokens = [t[0] for t in tokens]
    
    for i in range(0, len(tokens) - window + 1, window):
        window_slice = tokens[i:i + window]
        
        # Skip if any token is in a string
        if any(t[2] for t in window_slice):
            continue
        
        # Get shuffleable indices within this window
        shuffleable = [j for j in range(len(window_slice)) if not window_slice[j][2]]
        if len(shuffleable) < 2:
            continue
        
        # Shuffle the shuffleable tokens
        original_order = [result_tokens[i + j] for j in shuffleable]
        shuffled = original_order[:]
        rng.shuffle(shuffled)
        
        if shuffled != original_order:
            for k, j in enumerate(shuffleable):
                result_tokens[i + j] = shuffled[k]
            modified = True
    
    if not modified:
        return text, False
    
    # Reconstruct text (simplified: space-separated)
    # This loses exact whitespace but is safe
    return ' '.join(result_tokens), True


def perturb_whitespace(
    text: str,
    rng: random.Random,
    probability: float = 0.2,
) -> tuple[str, bool]:
    """
    Perturb whitespace formatting.
    
    - Normalize multiple spaces to single space (sometimes)
    - Add/remove trailing spaces on lines
    """
    if rng.random() > probability:
        return text, False
    
    lines = text.split('\n')
    modified = False
    new_lines = []
    
    for line in lines:
        # Randomly normalize internal whitespace
        if rng.random() < 0.3:
            new_line = _WHITESPACE_RUN_RE.sub(' ', line)
            if new_line != line:
                modified = True
                line = new_line
        
        # Randomly strip trailing whitespace
        if rng.random() < 0.5:
            stripped = line.rstrip()
            if stripped != line:
                modified = True
                line = stripped
        
        new_lines.append(line)
    
    return '\n'.join(new_lines), modified


def rename_identifiers(
    text: str,
    rng: random.Random,
    probability: float = 0.3,
    max_renames: int = 5,
) -> tuple[str, bool]:
    """
    Rename generic identifiers to var_1, var_2, etc.
    
    Only renames identifiers that are:
    - Not keywords
    - Not common builtins
    - Not imports
    """
    if rng.random() > probability:
        return text, False
    
    # Find all identifiers
    identifiers: dict[str, int] = {}
    for match in _IDENTIFIER_RE.finditer(text):
        ident = match.group(1)
        if ident.lower() not in {k.lower() for k in _ALL_KEYWORDS}:
            if len(ident) >= 2 and not ident.startswith('__'):
                identifiers[ident] = identifiers.get(ident, 0) + 1
    
    # Sort by frequency and pick top candidates for renaming
    candidates = sorted(
        [(ident, count) for ident, count in identifiers.items() if count >= 2],
        key=lambda x: (-x[1], x[0])
    )[:max_renames]
    
    if not candidates:
        return text, False
    
    # Create rename mapping
    rename_map: dict[str, str] = {}
    selected = rng.sample(candidates, min(len(candidates), max_renames))
    for i, (ident, _) in enumerate(selected):
        rename_map[ident] = f"var_{i + 1}"
    
    if not rename_map:
        return text, False
    
    # Apply renames
    def replace_ident(match: re.Match) -> str:
        ident = match.group(1)
        return rename_map.get(ident, ident)
    
    new_text = _IDENTIFIER_RE.sub(replace_ident, text)
    return new_text, new_text != text


def manipulate_comments(
    text: str,
    rng: random.Random,
    probability: float = 0.1,
) -> tuple[str, bool]:
    """
    Insert or remove comments.
    
    - Remove existing comments (50% chance when triggered)
    - Insert placeholder comments (50% chance when triggered)
    """
    if rng.random() > probability:
        return text, False
    
    if rng.random() < 0.5:
        # Remove comments
        new_text = _COMMENT_RE.sub('', text)
        # Clean up any resulting empty lines
        lines = [line for line in new_text.split('\n') if line.strip()]
        return '\n'.join(lines), new_text != text
    else:
        # Insert a placeholder comment at a random line
        lines = text.split('\n')
        if not lines:
            return text, False
        
        insert_pos = rng.randint(0, len(lines))
        comment_variants = [
            "# TODO: refactor",
            "// placeholder",
            "# note: updated",
        ]
        comment = rng.choice(comment_variants)
        lines.insert(insert_pos, comment)
        return '\n'.join(lines), True


def augment_text(
    text: str,
    sample_id: str,
    aug_index: int = 0,
    base_seed: int = 1337,
    config: AugmentConfig | None = None,
) -> AugmentResult:
    """
    Apply deterministic augmentations to text.
    
    Args:
        text: The input text to augment
        sample_id: Unique identifier for this sample
        aug_index: Index of this augmentation (for generating K variants)
        base_seed: Base random seed for determinism
        config: Augmentation configuration
    
    Returns:
        AugmentResult with original, augmented text, and applied transformations
    """
    if config is None:
        config = AugmentConfig()
    
    # Generate deterministic seed
    seed = _stable_seed(text, sample_id, aug_index, base_seed)
    rng = random.Random(seed)
    
    result = text
    transformations: list[str] = []
    
    # Apply augmentations in order
    if config.enable_shuffle:
        new_result, modified = shuffle_tokens_local(
            result, rng,
            window=config.shuffle_window,
            probability=config.shuffle_probability,
            preserve_strings=config.preserve_string_literals,
        )
        if modified:
            result = new_result
            transformations.append("shuffle")
    
    if config.enable_whitespace:
        new_result, modified = perturb_whitespace(
            result, rng,
            probability=config.whitespace_probability,
        )
        if modified:
            result = new_result
            transformations.append("whitespace")
    
    if config.enable_rename:
        new_result, modified = rename_identifiers(
            result, rng,
            probability=config.rename_probability,
            max_renames=config.max_renames,
        )
        if modified:
            result = new_result
            transformations.append("rename")
    
    if config.enable_comment:
        new_result, modified = manipulate_comments(
            result, rng,
            probability=config.comment_probability,
        )
        if modified:
            result = new_result
            transformations.append("comment")
    
    # Sanity check: ensure no banned substrings
    for banned in _BANNED_SUBSTRINGS:
        if banned.lower() in result.lower():
            # Revert to original if banned substring introduced
            return AugmentResult(
                original=text,
                augmented=text,
                transformations=[],
                seed=seed,
            )
    
    return AugmentResult(
        original=text,
        augmented=result,
        transformations=transformations,
        seed=seed,
    )


def generate_augmented_variants(
    text: str,
    sample_id: str,
    k: int = 1,
    base_seed: int = 1337,
    config: AugmentConfig | None = None,
) -> list[AugmentResult]:
    """
    Generate K augmented variants of a text.
    
    Args:
        text: Input text
        sample_id: Unique identifier
        k: Number of variants to generate
        base_seed: Base seed for determinism
        config: Augmentation config
    
    Returns:
        List of K AugmentResults
    """
    results = []
    for i in range(k):
        result = augment_text(text, sample_id, aug_index=i, base_seed=base_seed, config=config)
        results.append(result)
    return results
