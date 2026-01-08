from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import torch
from torch import nn

from ml.data.gnn_collate import collate_graph_samples
from ml.data.gnn_dataset import GraphSample
from ml.graphs.python_graph import build_python_graphs
from ml.graphs.ts_graph import build_ts_graphs
from ml.models.gnn import GraphClassifier
from ml.models.transformer import SimpleVocab, build_model, tokenize_text


@dataclass
class OODStats:
    mean: torch.Tensor
    inv_cov: torch.Tensor


def fit_temperature(logits: torch.Tensor, labels: torch.Tensor) -> float:
    temperature = torch.nn.Parameter(torch.ones(1))
    optimizer = torch.optim.LBFGS([temperature], max_iter=50)
    loss_fn = nn.BCEWithLogitsLoss()
    labels = labels.float()

    def closure() -> torch.Tensor:
        optimizer.zero_grad()
        loss = loss_fn(logits / temperature, labels)
        loss.backward()
        return loss

    optimizer.step(closure)
    return float(max(temperature.item(), 1e-3))


def compute_entropy(probs: torch.Tensor) -> torch.Tensor:
    eps = 1e-8
    probs = probs.clamp(min=eps, max=1 - eps)
    return -torch.sum(probs * torch.log(probs), dim=-1)


def weighted_average(probs: list[float], weights: list[float]) -> float:
    total = sum(weights)
    if total <= 0:
        return float(sum(probs) / max(len(probs), 1))
    return float(sum(p * w for p, w in zip(probs, weights)) / total)


def fit_embedding_stats(embeddings: torch.Tensor) -> OODStats:
    mean = embeddings.mean(dim=0)
    centered = embeddings - mean
    cov = (centered.T @ centered) / max(embeddings.size(0) - 1, 1)
    cov = cov + torch.eye(cov.size(0), device=cov.device) * 1e-3
    inv_cov = torch.linalg.pinv(cov)
    return OODStats(mean=mean, inv_cov=inv_cov)


def mahalanobis_distance(embedding: torch.Tensor, stats: OODStats) -> float:
    delta = (embedding - stats.mean).unsqueeze(0)
    dist = torch.sqrt((delta @ stats.inv_cov @ delta.T).squeeze())
    return float(dist.item())


def detect_ood(
    entropy_value: float,
    entropy_threshold: float,
    distance_value: float | None,
    distance_threshold: float | None,
) -> tuple[bool, str | None]:
    if distance_value is not None and distance_threshold is not None:
        if distance_value > distance_threshold:
            return True, "embedding_distance"
    if entropy_value > entropy_threshold:
        return True, "entropy"
    return False, None


class Stacker(nn.Module):
    def __init__(self, in_dim: int) -> None:
        super().__init__()
        self.linear = nn.Linear(in_dim, 1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.linear(x).squeeze(-1)


def train_stacker(features: torch.Tensor, labels: torch.Tensor, epochs: int = 100) -> Stacker:
    model = Stacker(features.size(1))
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-2)
    loss_fn = nn.BCEWithLogitsLoss()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits = model(features)
        loss = loss_fn(logits, labels)
        loss.backward()
        optimizer.step()
    return model


def _load_transformer(checkpoint_path: Path, device: torch.device):
    ckpt = torch.load(checkpoint_path, map_location=device, weights_only=False)
    token_to_id = ckpt["vocab"]
    id_to_token = [None] * (max(token_to_id.values()) + 1)
    for token, idx in token_to_id.items():
        id_to_token[idx] = token
    vocab = SimpleVocab(token_to_id=token_to_id, id_to_token=id_to_token)
    model = build_model(
        model_name=ckpt["model_name"],
        num_categories=len(ckpt["category_vocab"]),
        vocab_size=vocab.size,
        max_len=ckpt["max_len"],
        random_init=True,
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    return model, vocab, ckpt


def _load_gnn(checkpoint_path: Path, device: torch.device):
    ckpt = torch.load(checkpoint_path, map_location=device, weights_only=False)
    model = GraphClassifier(
        num_categories=len(ckpt["category_vocab"]),
        hidden_dim=ckpt["hidden_dim"],
        num_layers=ckpt["layers"],
        dropout=ckpt["dropout"],
    ).to(device)
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    return model, ckpt


def _encode_transformer(model, vocab, max_len: int, item: dict[str, Any], device: torch.device):
    tokens = item.get("tokens")
    if isinstance(tokens, list) and tokens:
        token_list = [str(tok) for tok in tokens]
    else:
        text = "\n".join(
            [
                item.get("context_before") or "",
                item.get("code_snippet") or item.get("code") or "",
                item.get("context_after") or "",
            ]
        )
        token_list = tokenize_text(text)
    input_ids, attention = vocab.encode(token_list, max_len)
    input_ids = torch.tensor([input_ids], dtype=torch.long, device=device)
    attention = torch.tensor([attention], dtype=torch.long, device=device)
    with torch.no_grad():
        cat_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention)
        emb = model.encode(input_ids=input_ids, attention_mask=attention)
    return risk_logit.squeeze(0), cat_logits.squeeze(0), emb.squeeze(0)


def _encode_gnn(model, item: dict[str, Any], device: torch.device):
    code = item.get("code_snippet") or item.get("code") or ""
    language = item.get("language") or "python"
    if language.startswith("py"):
        graphs = build_python_graphs(code)
    else:
        graphs = build_ts_graphs(code, language=language)
    if not graphs:
        return None, None, None
    graph = graphs[0]
    sample = GraphSample(
        sample_id=item.get("sample_id", ""), graph=graph, risk_label=0, category=""
    )
    batch = collate_graph_samples([sample], {"": 0})
    batch = _move_batch(batch, device)
    with torch.no_grad():
        risk_logit, cat_logits = model(batch)
        emb = model.encode(batch).squeeze(0)
    return risk_logit.squeeze(0), cat_logits.squeeze(0), emb


def _move_batch(batch, device: torch.device):
    batch.node_type_ids = batch.node_type_ids.to(device)
    batch.ident_hash_ids = batch.ident_hash_ids.to(device)
    batch.literal_flags = batch.literal_flags.to(device)
    batch.node_depth = batch.node_depth.to(device)
    batch.edge_index = batch.edge_index.to(device)
    batch.batch_index = batch.batch_index.to(device)
    return batch


def score(args: argparse.Namespace) -> None:
    device = torch.device(args.device)
    transformer, vocab, t_ckpt = _load_transformer(Path(args.transformer), device)
    gnn, g_ckpt = _load_gnn(Path(args.gnn), device)

    items = [
        json.loads(line)
        for line in Path(args.input).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    outputs: list[dict[str, Any]] = []
    temp = t_ckpt.get("temperature_risk", 1.0)
    ood_stats: OODStats | None = None

    if args.fit_ood_stats:
        embeddings = []
        for item in items:
            t_risk_logit, t_cat_logits, t_emb = _encode_transformer(
                transformer, vocab, t_ckpt["max_len"], item, device
            )
            g_risk_logit, g_cat_logits, g_emb = _encode_gnn(gnn, item, device)
            if g_risk_logit is None:
                continue
            embeddings.append(torch.cat([t_emb, g_emb]).cpu())
        if embeddings:
            emb_tensor = torch.stack(embeddings)
            ood_stats = fit_embedding_stats(emb_tensor)

    for item in items:
        t_risk_logit, t_cat_logits, t_emb = _encode_transformer(
            transformer, vocab, t_ckpt["max_len"], item, device
        )
        g_risk_logit, g_cat_logits, g_emb = _encode_gnn(gnn, item, device)
        if g_risk_logit is None:
            continue
        t_risk_prob = torch.sigmoid(t_risk_logit / temp).item()
        g_risk_prob = torch.sigmoid(g_risk_logit).item()

        risk_score = weighted_average([t_risk_prob, g_risk_prob], [args.w_transformer, args.w_gnn])
        t_cat_prob = torch.sigmoid(t_cat_logits).cpu()
        g_cat_prob = torch.sigmoid(g_cat_logits).cpu()
        cat_prob = (t_cat_prob + g_cat_prob) / 2
        entropy = float(compute_entropy(cat_prob).item())
        distance_value = None
        if ood_stats is not None:
            distance_value = mahalanobis_distance(torch.cat([t_emb.cpu(), g_emb.cpu()]), ood_stats)
        ood_flag, ood_reason = detect_ood(
            entropy,
            args.entropy_threshold,
            distance_value,
            args.distance_threshold if ood_stats else None,
        )

        topk = torch.topk(cat_prob, k=min(args.top_k, cat_prob.numel()))
        top_categories = [
            {"category": t_ckpt["category_vocab"][idx], "confidence": float(score)}
            for idx, score in zip(topk.indices.tolist(), topk.values.tolist())
        ]
        outputs.append(
            {
                "sample_id": item.get("sample_id"),
                "risk_score": risk_score,
                "confidence": float(max(t_risk_prob, g_risk_prob)),
                "top_categories": top_categories,
                "manual_review": ood_flag,
                "ood_reason": ood_reason,
            }
        )

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(outputs, indent=2), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ensemble scorer for transformer + GNN")
    parser.add_argument("--transformer", required=True)
    parser.add_argument("--gnn", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--w-transformer", type=float, default=0.6)
    parser.add_argument("--w-gnn", type=float, default=0.4)
    parser.add_argument("--entropy-threshold", type=float, default=1.2)
    parser.add_argument("--distance-threshold", type=float, default=5.0)
    parser.add_argument("--fit-ood-stats", action="store_true")
    parser.add_argument("--top-k", type=int, default=3)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    score(args)


if __name__ == "__main__":
    main()
