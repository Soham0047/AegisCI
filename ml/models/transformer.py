from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import torch
from torch import nn
from transformers import AutoConfig, AutoModel, DistilBertConfig, RobertaConfig

SPECIAL_TOKENS = ("[PAD]", "[CLS]", "[SEP]", "[UNK]")

# Code-aware tokenization pattern
CODE_TOKEN_PATTERN = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_]*|"  # Identifiers
    r"0[xX][0-9a-fA-F]+|"  # Hex numbers
    r"[0-9]+\.?[0-9]*(?:[eE][+-]?[0-9]+)?|"  # Numbers (including floats and scientific)
    r"\"\"\".*?\"\"\"|"  # Triple-quoted strings
    r"\'\'\'.*?\'\'\'|"  # Triple-quoted strings (single)
    r'"(?:[^"\\]|\\.)*"|'  # Double-quoted strings
    r"'(?:[^'\\]|\\.)*'|"  # Single-quoted strings
    r"[+\-*/%=<>!&|^~@]+|"  # Operators
    r"[(){}\[\],.:;])",  # Punctuation
    re.DOTALL,
)


def tokenize_text(text: str) -> list[str]:
    """Code-aware tokenization that preserves structure."""
    tokens = CODE_TOKEN_PATTERN.findall(text)
    # Also split on whitespace for any missed tokens
    if not tokens:
        tokens = text.split()
    return [t for t in tokens if t.strip()]


@dataclass
class SimpleVocab:
    token_to_id: dict[str, int]
    id_to_token: list[str]
    pad_id: int = 0
    cls_id: int = 1
    sep_id: int = 2
    unk_id: int = 3

    @classmethod
    def build(cls, token_lists: Iterable[Sequence[str]], min_freq: int = 1) -> SimpleVocab:
        counts: Counter[str] = Counter()
        for tokens in token_lists:
            counts.update(tokens)
        id_to_token = list(SPECIAL_TOKENS)
        for token, freq in counts.items():
            if freq < min_freq or token in SPECIAL_TOKENS:
                continue
            id_to_token.append(token)
        token_to_id = {token: idx for idx, token in enumerate(id_to_token)}
        return cls(token_to_id=token_to_id, id_to_token=id_to_token)

    @property
    def size(self) -> int:
        return len(self.id_to_token)

    def encode(self, tokens: Sequence[str], max_len: int) -> tuple[list[int], list[int]]:
        ids = [self.cls_id]
        ids.extend(self.token_to_id.get(token, self.unk_id) for token in tokens)
        ids.append(self.sep_id)
        if len(ids) > max_len:
            ids = ids[:max_len]
            ids[-1] = self.sep_id
        attention = [1] * len(ids)
        pad_len = max_len - len(ids)
        if pad_len > 0:
            ids.extend([self.pad_id] * pad_len)
            attention.extend([0] * pad_len)
        return ids, attention


def build_encoder_config(model_name: str, vocab_size: int, max_len: int) -> AutoConfig:
    if model_name == "tiny":
        return RobertaConfig(
            vocab_size=vocab_size,
            hidden_size=64,
            intermediate_size=256,
            num_hidden_layers=2,
            num_attention_heads=2,
            max_position_embeddings=max_len + 2,
            pad_token_id=0,
        )
    if model_name == "small":
        # Better capacity for multi-task learning
        return RobertaConfig(
            vocab_size=vocab_size,
            hidden_size=256,
            intermediate_size=1024,
            num_hidden_layers=4,
            num_attention_heads=4,
            max_position_embeddings=max_len + 2,
            pad_token_id=0,
            hidden_dropout_prob=0.1,
            attention_probs_dropout_prob=0.1,
        )
    if model_name == "medium":
        # Good balance of speed and performance
        return RobertaConfig(
            vocab_size=vocab_size,
            hidden_size=512,
            intermediate_size=2048,
            num_hidden_layers=6,
            num_attention_heads=8,
            max_position_embeddings=max_len + 2,
            pad_token_id=0,
            hidden_dropout_prob=0.1,
            attention_probs_dropout_prob=0.1,
        )
    if "roberta" in model_name:
        config = RobertaConfig()
    elif "distilbert" in model_name:
        config = DistilBertConfig()
    else:
        config = AutoConfig.from_pretrained(model_name, local_files_only=True)
    config.vocab_size = vocab_size
    config.max_position_embeddings = max_len + 2
    config.pad_token_id = 0
    return config


def build_model(
    model_name: str,
    num_categories: int,
    vocab_size: int,
    max_len: int,
    random_init: bool = True,
) -> TransformerClassifier:
    if random_init or model_name == "tiny":
        config = build_encoder_config(model_name, vocab_size=vocab_size, max_len=max_len)
        encoder = AutoModel.from_config(config)
    else:
        encoder = AutoModel.from_pretrained(model_name)
    return TransformerClassifier(encoder=encoder, num_categories=num_categories)


class TransformerClassifier(nn.Module):
    def __init__(self, encoder: nn.Module, num_categories: int, dropout: float = 0.1) -> None:
        super().__init__()
        self.encoder = encoder
        hidden_size = getattr(encoder.config, "hidden_size", None)
        if hidden_size is None:
            raise ValueError("Encoder config missing hidden_size")

        self.dropout = nn.Dropout(dropout)

        # Better classification head with hidden layer
        self.category_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 2, num_categories),
        )

        self.risk_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size // 2, 1),
        )

    def encode(self, input_ids: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = getattr(outputs, "pooler_output", None)
        if pooled is None:
            pooled = outputs.last_hidden_state[:, 0]
        return self.dropout(pooled)

    def forward(
        self, input_ids: torch.Tensor, attention_mask: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        pooled = self.encode(input_ids=input_ids, attention_mask=attention_mask)
        category_logits = self.category_head(pooled)
        risk_logit = self.risk_head(pooled).squeeze(-1)
        return category_logits, risk_logit

    @torch.no_grad()
    def predict(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
        temperature_risk: float = 1.0,
        temperature_cat: float | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        self.eval()
        cat_logits, risk_logit = self(input_ids=input_ids, attention_mask=attention_mask)
        temp_cat = temperature_cat or 1.0
        risk_score = torch.sigmoid(risk_logit / temperature_risk)
        category_scores = torch.sigmoid(cat_logits / temp_cat)
        return risk_score, category_scores
