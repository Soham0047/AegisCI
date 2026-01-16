from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import time
from pathlib import Path


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    print(f"    $ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)


def _gsutil_path(bucket: str, prefix: str) -> str:
    base = bucket.rstrip("/")
    prefix = prefix.strip("/")
    return f"{base}/{prefix}" if prefix else base


def _ensure_gsutil() -> None:
    if shutil.which("gsutil") is None:
        raise SystemExit("gsutil is required in the training container")


def download_from_gcs(bucket: str, prefix: str, dest: Path) -> None:
    _ensure_gsutil()
    dest.mkdir(parents=True, exist_ok=True)
    src = _gsutil_path(bucket, prefix)
    _run(["gsutil", "-m", "rsync", "-r", src, str(dest)])


def upload_to_gcs(src: Path, bucket: str, prefix: str) -> None:
    _ensure_gsutil()
    dest = _gsutil_path(bucket, prefix)
    _run(["gsutil", "-m", "rsync", "-r", str(src), dest])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureDev Guardian cloud training entrypoint")
    parser.add_argument("--datasets-bucket", required=True, help="GCS bucket for datasets")
    parser.add_argument("--models-bucket", required=True, help="GCS bucket for model artifacts")
    parser.add_argument("--dataset-prefix", default="datasets", help="Prefix for datasets in GCS")
    parser.add_argument("--output-prefix", default="models", help="Prefix for models in GCS")
    parser.add_argument("--repos-bucket", default="", help="GCS bucket with repos (optional)")
    parser.add_argument("--repos-prefix", default="repos", help="Prefix for repos in GCS")
    parser.add_argument(
        "--run-data-pipeline", action="store_true", help="Run data pipeline in cloud"
    )
    parser.add_argument("--max-files", type=int, default=600, help="Max files per repo")
    parser.add_argument("--max-samples", type=int, default=15000, help="Max safe samples per repo")
    parser.add_argument("--balance-mode", default="ratio", help="Balance mode")
    parser.add_argument("--max-safe-ratio", type=float, default=10.0, help="Max safe ratio")
    parser.add_argument(
        "--min-pos-per-category", type=int, default=0, help="Min positives per category"
    )
    parser.add_argument(
        "--max-pos-per-category", type=int, default=0, help="Max positives per category"
    )
    parser.add_argument(
        "--augment-contexts", default="3", help="Context sizes for vuln augmentation"
    )
    parser.add_argument("--semgrep-config", default="max", help="Semgrep config for data pipeline")
    parser.add_argument(
        "--semgrep-experimental",
        action="store_true",
        help="Include Semgrep experimental rules",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="MEDIUM",
        help="Minimum confidence to keep a finding",
    )
    parser.add_argument(
        "--auto-relax",
        action="store_true",
        help="Relax filters if no findings are produced",
    )
    parser.add_argument(
        "--fail-on-empty",
        action="store_true",
        help="Fail the pipeline if no findings/vulnerable samples are produced",
    )
    parser.add_argument(
        "--rule-allowlist",
        default="",
        help="Comma-separated list or file path of allowed rule IDs",
    )
    parser.add_argument(
        "--category-allowlist",
        default="",
        help="Comma-separated list or file path of allowed categories",
    )
    parser.add_argument("--epochs", type=int, default=20, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--device", default="cpu", help="Training device")
    parser.add_argument("--transformer-size", default="medium", help="Transformer size preset")
    parser.add_argument("--gnn-hidden-dim", type=int, default=256, help="GNN hidden dim")
    parser.add_argument("--gnn-layers", type=int, default=3, help="GNN layers")
    parser.add_argument("--gnn-dropout", type=float, default=0.2, help="GNN dropout")
    parser.add_argument("--risk-weight", type=float, default=1.0, help="Risk loss weight")
    parser.add_argument("--cat-weight", type=float, default=1.0, help="Category loss weight")
    parser.add_argument("--warmup-risk-epochs", type=int, default=0, help="Risk-only warmup epochs")
    parser.add_argument("--focal-loss", action="store_true", help="Use focal loss for risk head")
    parser.add_argument("--focal-alpha", type=float, default=0.25, help="Focal loss alpha")
    parser.add_argument("--focal-gamma", type=float, default=2.0, help="Focal loss gamma")
    parser.add_argument("--run-eval", action="store_true", help="Run eval after training")
    parser.add_argument("--eval-only", action="store_true", help="Skip training; run eval only")
    parser.add_argument(
        "--eval-model-prefix",
        default="",
        help="GCS prefix for models to evaluate (required for eval-only)",
    )
    return parser


def _run_eval(models_dir: Path, datasets_dir: Path, device: str, batch_size: int) -> None:
    metrics_dir = models_dir / "metrics"
    metrics_dir.mkdir(parents=True, exist_ok=True)

    transformer_ckpt = models_dir / "transformer_enhanced.pt"
    transformer_test = datasets_dir / "transformer" / "test.jsonl"
    if transformer_ckpt.exists() and transformer_test.exists():
        _run(
            [
                "python3",
                "-m",
                "ml.evaluate",
                "--checkpoint",
                str(transformer_ckpt),
                "--test",
                str(transformer_test),
                "--batch-size",
                str(batch_size),
                "--device",
                device,
                "--output",
                str(metrics_dir / "transformer_eval.json"),
            ]
        )
    else:
        print("    WARNING: Transformer eval skipped (missing checkpoint or test set)")

    gnn_ckpt = models_dir / "gnn_enhanced.pt"
    gnn_test = datasets_dir / "gnn" / "test.jsonl"
    if gnn_ckpt.exists() and gnn_test.exists():
        _run(
            [
                "python3",
                "-m",
                "ml.evaluate_gnn",
                "--checkpoint",
                str(gnn_ckpt),
                "--test",
                str(gnn_test),
                "--batch-size",
                str(batch_size),
                "--device",
                device,
                "--output",
                str(metrics_dir / "gnn_eval.json"),
            ]
        )
    else:
        print("    WARNING: GNN eval skipped (missing checkpoint or test set)")


def main() -> None:
    args = build_parser().parse_args()

    workdir = Path(os.environ.get("SECUREDEV_WORKDIR", "/tmp/securedev"))
    datasets_dir = workdir / "datasets"
    models_dir = workdir / "models"
    repos_dir = workdir / "repos"

    print("[cloud_train] preparing workspace")
    workdir.mkdir(parents=True, exist_ok=True)

    if args.eval_only:
        if not args.eval_model_prefix:
            raise SystemExit("--eval-model-prefix is required when --eval-only is set")

        print("[cloud_train] downloading datasets")
        download_from_gcs(args.datasets_bucket, args.dataset_prefix, datasets_dir)

        print("[cloud_train] downloading models")
        download_from_gcs(args.models_bucket, args.eval_model_prefix, models_dir)

        print("[cloud_train] running eval")
        _run_eval(models_dir, datasets_dir, args.device, args.batch_size)

        print("[cloud_train] uploading metrics")
        upload_to_gcs(
            models_dir / "metrics", args.models_bucket, f"{args.eval_model_prefix}/metrics"
        )
        print("[cloud_train] complete")
        return

    if args.run_data_pipeline:
        if not args.repos_bucket:
            raise SystemExit("--repos-bucket is required when --run-data-pipeline is set")
        print("[cloud_train] downloading repos")
        download_from_gcs(args.repos_bucket, args.repos_prefix, repos_dir)

        print("[cloud_train] running data pipeline")
        cmd = [
            "python3",
            "-m",
            "ml.data_pipeline",
            "--repos-dir",
            str(repos_dir),
            "--output-dir",
            str(datasets_dir),
            "--max-files",
            str(args.max_files),
            "--max-samples",
            str(args.max_samples),
            "--balance-mode",
            args.balance_mode,
            "--max-safe-ratio",
            str(args.max_safe_ratio),
            "--min-pos-per-category",
            str(args.min_pos_per_category),
            "--max-pos-per-category",
            str(args.max_pos_per_category),
            "--augment-contexts",
            args.augment_contexts,
            "--semgrep-config",
            args.semgrep_config,
            "--min-confidence",
            args.min_confidence,
            "--rule-allowlist",
            args.rule_allowlist,
            "--category-allowlist",
            args.category_allowlist,
            "--seed",
            str(args.seed),
            "--verbose",
        ]
        if args.semgrep_experimental:
            cmd.append("--semgrep-experimental")
        if args.auto_relax:
            cmd.append("--auto-relax")
        if args.fail_on_empty:
            cmd.append("--fail-on-empty")
        _run(cmd)

        print("[cloud_train] uploading datasets")
        upload_to_gcs(datasets_dir, args.datasets_bucket, args.dataset_prefix)
    else:
        print("[cloud_train] downloading datasets")
        download_from_gcs(args.datasets_bucket, args.dataset_prefix, datasets_dir)

    print("[cloud_train] training models")
    train_cmd = [
        "python3",
        "-m",
        "ml.train_pipeline",
        "--skip-scan",
        "--dataset",
        str(datasets_dir),
        "--output",
        str(models_dir),
        "--epochs",
        str(args.epochs),
        "--batch-size",
        str(args.batch_size),
        "--lr",
        str(args.lr),
        "--seed",
        str(args.seed),
        "--device",
        args.device,
        "--transformer-size",
        args.transformer_size,
        "--gnn-hidden-dim",
        str(args.gnn_hidden_dim),
        "--gnn-layers",
        str(args.gnn_layers),
        "--gnn-dropout",
        str(args.gnn_dropout),
        "--risk-weight",
        str(args.risk_weight),
        "--cat-weight",
        str(args.cat_weight),
        "--warmup-risk-epochs",
        str(args.warmup_risk_epochs),
        "--focal-alpha",
        str(args.focal_alpha),
        "--focal-gamma",
        str(args.focal_gamma),
    ]
    if args.focal_loss:
        train_cmd.append("--focal-loss")
    _run(train_cmd)

    if args.run_eval:
        print("[cloud_train] running eval")
        _run_eval(models_dir, datasets_dir, args.device, args.batch_size)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_prefix = args.output_prefix.rstrip("/")
    output_prefix = f"{output_prefix}/run-{timestamp}"

    print("[cloud_train] uploading models")
    upload_to_gcs(models_dir, args.models_bucket, output_prefix)

    print("[cloud_train] complete")
    print(f"models_gcs_prefix={_gsutil_path(args.models_bucket, output_prefix)}")


if __name__ == "__main__":
    main()
