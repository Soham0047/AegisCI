from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass

import torch
from torch import nn
from torch.nn import functional as F

logger = logging.getLogger(__name__)

# Environment variable to control pretrained model loading
PRETRAINED_MODEL_ENABLED = os.environ.get("DL_PRETRAINED_MODEL", "0") == "1"
PRETRAINED_MODEL_OFFLINE = os.environ.get("DL_PRETRAINED_OFFLINE", "1") == "1"


@dataclass
class EncoderConfig:
    vocab_size: int
    embed_dim: int
    hidden_dim: int
    max_len: int
    use_pretrained: bool = False
    pretrained_model_name: str = "microsoft/codebert-base"


class PretrainedCodeEncoder(nn.Module):
    """
    Optional pretrained code encoder using CodeBERT or CodeT5.
    
    Falls back gracefully to a simple embedding layer if:
    - Pretrained models are disabled
    - Required libraries (transformers) not installed
    - Model cannot be loaded (offline mode, network issues)
    """
    
    def __init__(
        self,
        model_name: str = "microsoft/codebert-base",
        hidden_dim: int = 96,
        offline_only: bool = True,
    ) -> None:
        super().__init__()
        self.model_name = model_name
        self.hidden_dim = hidden_dim
        self.offline_only = offline_only
        self._pretrained_loaded = False
        self._encoder = None
        self._tokenizer = None
        self._proj = None
        
        # Try to load pretrained model
        self._try_load_pretrained()
        
        # Fallback: simple learned embedding
        if not self._pretrained_loaded:
            logger.info("Using fallback embedding layer (no pretrained model)")
            self._fallback_embed = nn.Embedding(30000, hidden_dim, padding_idx=0)
            self._fallback_pool = nn.GRU(
                hidden_dim, hidden_dim, batch_first=True, bidirectional=True
            )
            self._fallback_proj = nn.Linear(hidden_dim * 2, hidden_dim)
    
    def _try_load_pretrained(self) -> None:
        """Attempt to load pretrained model with graceful fallback."""
        if not PRETRAINED_MODEL_ENABLED:
            logger.info("Pretrained model disabled (set DL_PRETRAINED_MODEL=1 to enable)")
            return
        
        try:
            from transformers import AutoModel, AutoTokenizer
            
            # Set offline mode if requested
            if self.offline_only or PRETRAINED_MODEL_OFFLINE:
                os.environ["TRANSFORMERS_OFFLINE"] = "1"
            
            logger.info(f"Loading pretrained model: {self.model_name}")
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_name, local_files_only=self.offline_only
            )
            self._encoder = AutoModel.from_pretrained(
                self.model_name, local_files_only=self.offline_only
            )
            
            # Freeze pretrained weights
            for param in self._encoder.parameters():
                param.requires_grad = False
            
            # Add projection layer
            encoder_dim = self._encoder.config.hidden_size
            self._proj = nn.Linear(encoder_dim, self.hidden_dim)
            self._pretrained_loaded = True
            logger.info(f"Successfully loaded pretrained model: {self.model_name}")
            
        except ImportError:
            logger.warning("transformers library not installed - using fallback")
        except OSError as e:
            logger.warning(f"Could not load pretrained model (offline?): {e}")
        except Exception as e:
            logger.warning(f"Pretrained model load failed: {e}")
    
    @property
    def is_pretrained(self) -> bool:
        """Check if pretrained model is active."""
        return self._pretrained_loaded
    
    def forward(self, tokens: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        """
        Encode tokens to embeddings.
        
        Args:
            tokens: Token IDs [batch, seq_len]
            lengths: Sequence lengths [batch]
        
        Returns:
            Normalized embeddings [batch, hidden_dim]
        """
        if self._pretrained_loaded and self._encoder is not None:
            # Use pretrained encoder
            attention_mask = (tokens != 0).long()
            outputs = self._encoder(tokens, attention_mask=attention_mask)
            # Mean pooling over sequence
            hidden = outputs.last_hidden_state
            mask = attention_mask.unsqueeze(-1).float()
            summed = (hidden * mask).sum(dim=1)
            pooled = summed / mask.sum(dim=1).clamp(min=1)
            projected = self._proj(pooled)
            return F.normalize(projected, p=2, dim=-1)
        else:
            # Fallback embedding
            embedded = self._fallback_embed(tokens)
            outputs, _ = self._fallback_pool(embedded)
            mask = (tokens != 0).unsqueeze(-1).float()
            summed = (outputs * mask).sum(dim=1)
            pooled = summed / lengths.clamp(min=1).unsqueeze(-1)
            projected = self._fallback_proj(pooled)
            return F.normalize(projected, p=2, dim=-1)


class DualEncoder(nn.Module):
    def __init__(self, config: EncoderConfig) -> None:
        super().__init__()
        self.config = config
        self.embedding = nn.Embedding(config.vocab_size, config.embed_dim, padding_idx=0)
        self.encoder = nn.GRU(
            input_size=config.embed_dim,
            hidden_size=config.hidden_dim,
            num_layers=1,
            batch_first=True,
            bidirectional=True,
        )
        self.proj = nn.Linear(config.hidden_dim * 2, config.hidden_dim)

    def forward(self, tokens: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        embedded = self.embedding(tokens)
        outputs, _ = self.encoder(embedded)
        mask = (tokens != 0).unsqueeze(-1)
        masked = outputs * mask
        summed = masked.sum(dim=1)
        lengths = lengths.clamp(min=1).unsqueeze(-1)
        pooled = summed / lengths
        projected = self.proj(pooled)
        return F.normalize(projected, p=2, dim=-1)

    def encode(self, tokens: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        self.eval()
        with torch.no_grad():
            return self.forward(tokens, lengths)


class RerankerMLP(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 128) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
        )

    def forward(self, features: torch.Tensor) -> torch.Tensor:
        return self.net(features).squeeze(-1)


def build_pair_features(query_emb: torch.Tensor, doc_emb: torch.Tensor) -> torch.Tensor:
    return torch.cat(
        [
            query_emb,
            doc_emb,
            torch.abs(query_emb - doc_emb),
            query_emb * doc_emb,
        ],
        dim=-1,
    )


def batch_lengths(tokens: torch.Tensor) -> torch.Tensor:
    lengths = (tokens != 0).sum(dim=1)
    return lengths


def to_device(tensors: Iterable[torch.Tensor], device: torch.device) -> list[torch.Tensor]:
    return [tensor.to(device) for tensor in tensors]
