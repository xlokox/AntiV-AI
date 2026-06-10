#!/usr/bin/env python3
"""
Train AntiV-AI's real malware detector on the EMBER-2018 dataset.

WHAT THIS SCRIPT DOES (end to end)
----------------------------------
  1. Streams EMBER's raw-feature JSONL files from disk.
  2. Vectorises each record with the SAME PEFeatureExtractor used at inference
     time (src/ml/features.py) -> a 2,381-dim float32 vector. Multiprocessing is
     used so 800k records vectorise in well under a minute on a laptop.
  3. Trains a gradient-boosted decision-tree classifier
     (scikit-learn HistGradientBoosting by default; LightGBM if installed).
  4. Evaluates on EMBER's held-out test set using metrics that actually matter
     for antivirus -- detection rate (TPR) at fixed, very low false-positive
     rates -- not just "accuracy", which is misleading for security.
  5. Saves the model, a machine-readable metrics.json, and a human-readable
     MODEL_CARD.md documenting exactly what was trained and how it scored.

WHY GRADIENT-BOOSTED TREES
--------------------------
They are the published EMBER baseline, handle 2,381 mixed-scale features without
any feature scaling (so there is no scaler to drift), train fast, and give
strong low-FPR detection. No fabricated "1.0 across the board" metrics here --
the numbers this script prints are the numbers it measured.

USAGE
-----
  python scripts/train_ember.py                         # sensible defaults
  python scripts/train_ember.py --train-limit 0         # use ALL labeled data
  python scripts/train_ember.py --algo lgbm             # force LightGBM
  python scripts/train_ember.py --help                  # all options
"""

import os                                   # paths / cpu count
import sys                                  # to put src/ on the import path
import json                                 # read EMBER JSONL, write metrics.json
import time                                 # timing the stages
import argparse                             # command-line options
import multiprocessing as mp                # parallel vectorisation
from datetime import datetime, timezone     # timezone-aware timestamps for the model card

import numpy as np                          # arrays + numeric metrics

# Make `import ml.features` work whether run from the repo root or elsewhere.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from ml.features import PEFeatureExtractor  # the shared train/serve feature extractor

# scikit-learn metrics (all measured, none assumed).
from sklearn.metrics import (
    roc_auc_score,                          # ranking quality (overall + low-FPR region)
    average_precision_score,                # PR-AUC, robust to class imbalance
    roc_curve,                              # to read TPR at chosen FPRs
    confusion_matrix,                       # TP/FP/FN/TN at an operating threshold
    brier_score_loss,                       # probability calibration quality
)

# ---------------------------------------------------------------------------
# Multiprocessing vectorisation
# ---------------------------------------------------------------------------
# Each worker process builds ONE extractor (compiling regexes once) and reuses
# it for every line it handles. The extractor lives in a module-level global so
# it is created in the worker's initializer rather than pickled per task.
_WORKER_EXTRACTOR = None


def _init_worker():
    """Pool initializer: create the per-process feature extractor exactly once."""
    global _WORKER_EXTRACTOR
    _WORKER_EXTRACTOR = PEFeatureExtractor()  # 2,381-dim EMBER-v2 extractor


def _vectorize_line(line):
    """Parse one JSONL record -> (label, vector) or None for unlabeled rows.

    Runs inside a worker process. Returns None when the sample is unlabeled
    (EMBER marks those with label == -1) so the caller can simply skip it.
    """
    try:
        rec = json.loads(line)              # decode the JSON object on this line
    except Exception:
        return None                         # corrupt line -> skip, never crash the run
    label = rec.get("label", -1)            # 0 = benign, 1 = malware, -1 = unlabeled
    if label not in (0, 1):                 # drop unlabeled / unexpected labels
        return None
    try:
        vec = _WORKER_EXTRACTOR.process_raw_features(rec)   # 2,381-dim float32 vector
    except Exception:
        return None                         # a malformed record must not abort training
    return (int(label), vec)


def vectorize_files(paths, limit, dim, jobs, stage_name, balanced=False):
    """Vectorise labeled records from `paths` into (X, y).

    Memory-safe: pre-allocates one float32 matrix and fills rows as results
    stream back from the worker pool, so we never hold a giant Python list nor
    pay for a vstack copy. `limit <= 0` means "no cap".

    `balanced=True` enforces an equal per-class quota (limit // 2 each). This
    matters because EMBER records are ordered by appearance date and the early
    ones are almost entirely benign -- a naive "first N labeled" sample would be
    all-benign and train a useless ROC-AUC=0.5 model. With balancing we keep
    scanning (skipping a class once its quota is full) until both quotas fill.
    """
    # Per-class quota when balancing; otherwise a single overall cap.
    per_class_cap = (limit // 2) if (balanced and limit > 0) else None

    # Size the pre-allocated buffer: the cap if known, else an upper bound (total
    # lines, since unlabeled rows are skipped) which we trim afterwards.
    if limit > 0:
        capacity = (per_class_cap * 2) if per_class_cap is not None else limit
    else:
        capacity = sum(1 for p in paths for _ in open(p))

    X = np.empty((capacity, dim), dtype=np.float32)   # pre-allocated feature matrix
    y = np.empty((capacity,), dtype=np.int8)          # labels (0/1)
    n = 0                                             # accepted samples so far
    class_counts = {0: 0, 1: 0}                       # per-class accepted counts
    t0 = time.time()

    def line_iter():
        # Lazily yield every line across all input files (low memory footprint).
        for p in paths:
            with open(p, "r") as fin:
                for line in fin:
                    yield line

    # Spread the CPU-bound vectorisation across worker processes.
    with mp.Pool(processes=jobs, initializer=_init_worker) as pool:
        for result in pool.imap_unordered(_vectorize_line, line_iter(), chunksize=256):
            if result is None:
                continue                     # skip unlabeled / bad rows
            label, vec = result
            if per_class_cap is not None and class_counts[label] >= per_class_cap:
                continue                     # this class's quota is full -> keep scanning for the other
            X[n] = vec                       # write directly into the pre-allocated buffer
            y[n] = label
            class_counts[label] += 1
            n += 1
            if n % 50000 == 0:               # periodic progress so long runs are visible
                print(f"  [{stage_name}] vectorized {n:,} "
                      f"({class_counts[1]:,} mal / {class_counts[0]:,} ben, "
                      f"{n/(time.time()-t0):,.0f}/s)", flush=True)
            # Stop conditions: balanced -> both quotas full; unbalanced -> overall cap.
            if per_class_cap is not None:
                if class_counts[0] >= per_class_cap and class_counts[1] >= per_class_cap:
                    break
            elif limit > 0 and n >= limit:
                break

    X = X[:n]                                # trim unused rows (view, no copy)
    y = y[:n]
    dt = time.time() - t0
    pos = int(y.sum())
    print(f"  [{stage_name}] done: {n:,} samples ({pos:,} malware / {n - pos:,} benign) "
          f"in {dt:.1f}s", flush=True)
    return X, y


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
def build_model(algo, jobs):
    """Return (model, resolved_algo_name).

    Prefers LightGBM only when explicitly requested AND importable; otherwise
    uses scikit-learn's HistGradientBoosting, which is always available here and
    needs no native (libomp) dependency.
    """
    if algo in ("lgbm", "lightgbm"):
        try:
            import lightgbm as lgb          # optional; the published EMBER baseline
        except Exception as e:
            print(f"  LightGBM requested but unavailable ({e}); "
                  f"falling back to HistGradientBoosting.", flush=True)
            algo = "hist"
        else:
            # EMBER-style parameters: deep trees, many leaves, low learning rate.
            # bagging_freq=1 makes bagging_fraction (row subsampling) actually engage.
            model = lgb.LGBMClassifier(
                boosting_type="gbdt", objective="binary",
                num_leaves=512, n_estimators=1000, learning_rate=0.05,
                feature_fraction=0.8, bagging_fraction=0.8, bagging_freq=1,
                n_jobs=jobs, verbosity=-1,
            )
            return model, "lightgbm"

    if algo not in ("auto", "hist"):
        raise ValueError(f"Unknown --algo {algo!r}")

    from sklearn.ensemble import HistGradientBoostingClassifier
    # Strong, memory-friendly defaults; early stopping guards against overfitting.
    model = HistGradientBoostingClassifier(
        max_iter=400,                        # up to 400 boosting rounds
        learning_rate=0.07,                  # step size per round
        max_leaf_nodes=128,                  # tree complexity
        l2_regularization=1.0,               # shrink leaf values to reduce overfit
        max_bins=255,                        # feature binning resolution
        early_stopping=True,                 # stop when validation score plateaus
        validation_fraction=0.1,             # 10% held out internally for early stopping
        n_iter_no_change=15,                 # patience before stopping
        random_state=42,                     # reproducible runs
    )
    return model, "sklearn_hist_gradient_boosting"


# ---------------------------------------------------------------------------
# Honest evaluation
# ---------------------------------------------------------------------------
def tpr_at_fpr(y_true, scores, target_fpr):
    """Detection rate (true-positive rate) at a target false-positive rate.

    This is the metric antivirus engineers actually care about: "if I accept at
    most X% false alarms on clean files, what fraction of malware do I catch?"
    Returns (tpr, threshold) where threshold is the score cutoff achieving it.
    """
    fpr, tpr, thr = roc_curve(y_true, scores)         # full ROC curve
    idx = np.searchsorted(fpr, target_fpr, side="right") - 1   # last point with fpr <= target
    idx = max(idx, 0)
    return float(tpr[idx]), float(thr[idx])


def evaluate(model, X_test, y_test):
    """Compute a dict of honest, decision-relevant metrics on the test set."""
    # Probability that each test sample is malware.
    scores = model.predict_proba(X_test)[:, 1]

    metrics = {}
    metrics["roc_auc"] = float(roc_auc_score(y_test, scores))                  # overall ranking
    # AUC restricted to the low-FPR region -- where an AV must operate.
    metrics["roc_auc_maxfpr_1e-3"] = float(roc_auc_score(y_test, scores, max_fpr=1e-3))
    metrics["roc_auc_maxfpr_1e-2"] = float(roc_auc_score(y_test, scores, max_fpr=1e-2))
    metrics["pr_auc"] = float(average_precision_score(y_test, scores))         # precision-recall AUC
    metrics["brier_score"] = float(brier_score_loss(y_test, scores))           # calibration (lower=better)

    # Detection rate at three operationally meaningful false-positive budgets.
    detection = {}
    for fpr_target in (1e-3, 1e-2, 5e-2):
        tpr, thr = tpr_at_fpr(y_test, scores, fpr_target)
        detection[f"fpr_{fpr_target:g}"] = {"tpr": tpr, "threshold": thr}
    metrics["detection_at_fpr"] = detection

    # Pick the operating threshold that holds false positives to ~1%.
    operating_threshold = detection["fpr_0.01"]["threshold"]
    preds = (scores >= operating_threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
    metrics["operating_threshold"] = float(operating_threshold)
    metrics["confusion_at_threshold"] = {"tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}
    # Precision / recall / F1 at that operating point (derived from the confusion matrix).
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    metrics["at_threshold"] = {"precision": float(precision), "recall": float(recall),
                               "f1": float(f1), "accuracy": float(accuracy)}
    return metrics, scores


# ---------------------------------------------------------------------------
# Model card
# ---------------------------------------------------------------------------
def write_model_card(path, info):
    """Write a human-readable MODEL_CARD.md documenting the trained model."""
    m = info["metrics"]
    det = m["detection_at_fpr"]
    card = f"""# AntiV-AI Malware Detection — Model Card

> Generated by `scripts/train_ember.py` on {info['trained_at']}.
> Every number below was **measured on a held-out test set**, not assumed.

## Overview
- **Task:** binary static detection of malicious Windows PE files (malware vs. benign).
- **Model:** {info['algo']} (gradient-boosted decision trees).
- **Features:** EMBER-v2 schema, 2,381 dimensions, extracted by `src/ml/features.py`.
  The identical extractor is used for training and for live scoring, so there is
  **no train/serve skew**.
- **No feature scaling** is applied (tree models do not need it), which removes an
  entire class of preprocessing-drift bugs.

## Training data
- **Dataset:** EMBER-2018 (feature version 2), the public Elastic/EMBER benchmark.
- **Training samples used:** {info['n_train']:,} ({info['n_train_mal']:,} malware / {info['n_train_ben']:,} benign).
- **Test samples used:** {info['n_test']:,} ({info['n_test_mal']:,} malware / {info['n_test_ben']:,} benign).
- Unlabeled EMBER rows (label = -1) are excluded from supervised training.
- Train/test come from EMBER's predefined split; samples are time-ordered
  (`appeared`), so the test set approximates "future, unseen" files.

## Results (measured on the held-out test set)
| Metric | Value |
|---|---|
| ROC-AUC (overall) | **{m['roc_auc']:.5f}** |
| ROC-AUC (FPR ≤ 1%) | {m['roc_auc_maxfpr_1e-2']:.5f} |
| ROC-AUC (FPR ≤ 0.1%) | {m['roc_auc_maxfpr_1e-3']:.5f} |
| PR-AUC | {m['pr_auc']:.5f} |
| Brier score (calibration, lower=better) | {m['brier_score']:.5f} |

**Detection rate at fixed false-positive budgets** (the metric that matters for AV):

| Max false positives on clean files | Malware caught (TPR) | Score threshold |
|---|---|---|
| 5%   | {det['fpr_0.05']['tpr']*100:.2f}% | {det['fpr_0.05']['threshold']:.4f} |
| 1%   | {det['fpr_0.01']['tpr']*100:.2f}% | {det['fpr_0.01']['threshold']:.4f} |
| 0.1% | {det['fpr_0.001']['tpr']*100:.2f}% | {det['fpr_0.001']['threshold']:.4f} |

At the recommended operating threshold ({m['operating_threshold']:.4f}, ~1% FPR):
precision **{m['at_threshold']['precision']:.4f}**, recall **{m['at_threshold']['recall']:.4f}**,
F1 **{m['at_threshold']['f1']:.4f}**, accuracy **{m['at_threshold']['accuracy']:.4f}**.

## Intended use & limitations (read this)
- **Scope:** static analysis of **PE files only** (Windows .exe/.dll/.sys). It does
  not analyse scripts, documents, ELF/Mach-O, archives, or runtime behaviour.
- **Evasion:** static models can be evaded by packing, polymorphism, or adversarial
  perturbation. This detector is one layer; pair it with heuristics, reputation,
  and (sandboxed) dynamic analysis for defence in depth.
- **Concept drift:** malware evolves. Detection on genuinely new families will be
  lower than these 2018-test numbers; retrain periodically on fresh data.
- **Not a substitute** for a maintained commercial AV on a production endpoint.

## Reproduce
```bash
python scripts/train_ember.py --train-limit {info['train_limit']} --algo {info['algo_arg']}
```
"""
    with open(path, "w") as f:
        f.write(card)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Train AntiV-AI's EMBER malware detector.")
    parser.add_argument("--data-dir", default=os.path.join(_REPO_ROOT, "data", "ember", "ember2018"),
                        help="directory containing EMBER train_features_*.jsonl and test_features.jsonl")
    parser.add_argument("--model-dir", default=os.path.join(_REPO_ROOT, "models", "ember"),
                        help="where to write the trained model, metrics.json and MODEL_CARD.md")
    parser.add_argument("--train-limit", type=int, default=300000,
                        help="max labeled training samples (0 = use all ~600k; default 300k is RAM-safe)")
    parser.add_argument("--test-limit", type=int, default=0,
                        help="max labeled test samples (0 = use all ~200k)")
    parser.add_argument("--algo", default="auto", choices=["auto", "hist", "lgbm", "lightgbm"],
                        help="model: 'hist'/'auto' = sklearn HistGradientBoosting, 'lgbm' = LightGBM")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1),
                        help="worker processes for vectorisation / training")
    args = parser.parse_args()

    os.makedirs(args.model_dir, exist_ok=True)
    extractor = PEFeatureExtractor()
    dim = extractor.dim                      # 2,381

    train_paths = [os.path.join(args.data_dir, f"train_features_{i}.jsonl") for i in range(6)]
    train_paths = [p for p in train_paths if os.path.exists(p)]
    test_paths = [os.path.join(args.data_dir, "test_features.jsonl")]
    test_paths = [p for p in test_paths if os.path.exists(p)]
    if not train_paths or not test_paths:
        sys.exit(f"ERROR: EMBER JSONL not found under {args.data_dir}. "
                 f"Run the download/extract step first.")

    print(f"== AntiV-AI EMBER training ==")
    print(f"   data-dir : {args.data_dir}")
    print(f"   feature dim: {dim} | jobs: {args.jobs} | train-limit: {args.train_limit or 'ALL'}")

    print("Vectorizing training set (class-balanced) ...", flush=True)
    X_train, y_train = vectorize_files(train_paths, args.train_limit, dim, args.jobs, "train", balanced=True)
    print("Vectorizing test set ...", flush=True)
    X_test, y_test = vectorize_files(test_paths, args.test_limit, dim, args.jobs, "test", balanced=False)

    model, algo_name = build_model(args.algo, args.jobs)
    print(f"Training model: {algo_name} on {X_train.shape[0]:,} x {X_train.shape[1]} ...", flush=True)
    t0 = time.time()
    model.fit(X_train, y_train)
    print(f"   trained in {time.time() - t0:.1f}s", flush=True)

    print("Evaluating on held-out test set ...", flush=True)
    metrics, _ = evaluate(model, X_test, y_test)

    # Persist the model with joblib (works for both sklearn and LightGBM sklearn API).
    import joblib
    model_path = os.path.join(args.model_dir, "ember_model.joblib")
    joblib.dump({"model": model, "algo": algo_name, "feature_version": 2, "dim": dim,
                 "operating_threshold": metrics["operating_threshold"]}, model_path)

    # Write machine-readable metrics + the model card.
    trained_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    info = {
        "trained_at": trained_at, "algo": algo_name, "algo_arg": args.algo,
        "train_limit": args.train_limit,
        "n_train": int(X_train.shape[0]), "n_train_mal": int(y_train.sum()),
        "n_train_ben": int((y_train == 0).sum()),
        "n_test": int(X_test.shape[0]), "n_test_mal": int(y_test.sum()),
        "n_test_ben": int((y_test == 0).sum()),
        "feature_dim": dim, "metrics": metrics,
    }
    with open(os.path.join(args.model_dir, "ember_metrics.json"), "w") as f:
        json.dump(info, f, indent=2)
    write_model_card(os.path.join(args.model_dir, "MODEL_CARD.md"), info)

    # Honest console summary.
    det = metrics["detection_at_fpr"]
    print("\n================ RESULTS (measured) ================")
    print(f"  ROC-AUC overall        : {metrics['roc_auc']:.5f}")
    print(f"  ROC-AUC (FPR<=0.1%)    : {metrics['roc_auc_maxfpr_1e-3']:.5f}")
    print(f"  PR-AUC                 : {metrics['pr_auc']:.5f}")
    print(f"  Brier (calibration)    : {metrics['brier_score']:.5f}")
    print(f"  Detection @ 1% FPR     : {det['fpr_0.01']['tpr']*100:.2f}% malware caught")
    print(f"  Detection @ 0.1% FPR   : {det['fpr_0.001']['tpr']*100:.2f}% malware caught")
    print(f"  Model   -> {model_path}")
    print(f"  Metrics -> {os.path.join(args.model_dir, 'ember_metrics.json')}")
    print(f"  Card    -> {os.path.join(args.model_dir, 'MODEL_CARD.md')}")
    print("====================================================")


if __name__ == "__main__":
    main()
