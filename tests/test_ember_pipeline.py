"""
Tests for the real EMBER-based ML pipeline.

These tests defend the property that broke the old "AI": that the feature
extractor used for INFERENCE produces the same kind of vector as the one used
for TRAINING (no train/serve skew), and that the trained model genuinely
separates malware from benign on held-out EMBER samples.

Most tests need the EMBER dataset and/or the trained model. When those are not
present, the relevant tests skip cleanly rather than fail, so the suite still
runs in a bare checkout.
"""

import os                                   # locate dataset/model files
import sys                                  # extend import path to src/
import json                                 # read EMBER raw records

import numpy as np                          # numeric assertions
import pytest                               # test framework + skip helpers

# Make `import ml.features` / `import ml.detector` resolve to src/ml.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from ml.features import PEFeatureExtractor  # the shared extractor under test

# Paths to the (optional) dataset and trained model.
_EMBER_DIR = os.path.join(_REPO_ROOT, "data", "ember", "ember2018")
_TRAIN_JSONL = os.path.join(_EMBER_DIR, "train_features_0.jsonl")
_TEST_JSONL = os.path.join(_EMBER_DIR, "test_features.jsonl")
_MODEL_PATH = os.path.join(_REPO_ROOT, "models", "ember", "ember_model.joblib")

# The nine feature-group keys an EMBER raw record must contain for the schema to
# line up with what the extractor expects.
_REQUIRED_GROUP_KEYS = {
    "histogram", "byteentropy", "strings", "general",
    "header", "section", "imports", "exports", "datadirectories",
}


def _read_records(path, n):
    """Read up to n JSON records from an EMBER JSONL file."""
    out = []
    with open(path, "r") as f:
        for i, line in enumerate(f):
            if i >= n:
                break
            out.append(json.loads(line))
    return out


# --------------------------------------------------------------------------
# Extractor: shape, schema, determinism (no dataset needed for shape/determinism)
# --------------------------------------------------------------------------
def test_extractor_dim_is_2381():
    """The EMBER-v2 vector must be exactly 2,381 dimensions."""
    ex = PEFeatureExtractor()
    assert ex.dim == 2381
    # The sum of the individual group dims must equal the total.
    assert sum(fe.dim for fe in ex.features) == 2381


def test_raw_features_on_arbitrary_bytes_is_safe():
    """Non-PE bytes must not crash and must still yield a full-width vector."""
    ex = PEFeatureExtractor()
    raw = ex.raw_features(b"this is clearly not a PE file " * 100)   # arbitrary bytes
    vec = ex.process_raw_features(raw)
    assert vec.shape == (2381,)                       # full width even with no PE structure
    assert np.isfinite(vec).all()                     # no NaN/inf from empty PE fields


@pytest.mark.skipif(not os.path.exists(_TRAIN_JSONL), reason="EMBER dataset not present")
def test_real_records_match_schema_and_vectorize():
    """Every real EMBER record must contain the keys the extractor reads."""
    ex = PEFeatureExtractor()
    for rec in _read_records(_TRAIN_JSONL, 200):
        # Schema parity: this is exactly the property whose absence broke the old AI.
        assert _REQUIRED_GROUP_KEYS.issubset(rec.keys())
        vec = ex.process_raw_features(rec)
        assert vec.shape == (2381,)
        assert np.isfinite(vec).all()


@pytest.mark.skipif(not os.path.exists(_TRAIN_JSONL), reason="EMBER dataset not present")
def test_vectorization_is_deterministic():
    """Vectorising the same record twice must give identical results."""
    ex = PEFeatureExtractor()
    rec = _read_records(_TRAIN_JSONL, 1)[0]
    v1 = ex.process_raw_features(rec)
    v2 = ex.process_raw_features(rec)
    assert np.array_equal(v1, v2)                     # bit-for-bit identical -> no hidden randomness


# --------------------------------------------------------------------------
# Trained model: genuine separation between malware and benign
# --------------------------------------------------------------------------
@pytest.mark.skipif(not (os.path.exists(_MODEL_PATH) and os.path.exists(_TEST_JSONL)),
                    reason="trained model or EMBER test set not present")
def test_model_separates_malware_from_benign():
    """On held-out EMBER test records the model must score malware >> benign.

    This is the anti-'fake AI' test: a model trained on random data (the old
    behaviour) would score ~0.5 for everything and fail this assertion.
    """
    import joblib
    bundle = joblib.load(_MODEL_PATH)
    model = bundle["model"]
    ex = PEFeatureExtractor()

    # Collect a few hundred labeled test records of each class.
    benign_probs, malware_probs = [], []
    for rec in _read_records(_TEST_JSONL, 1500):
        label = rec.get("label", -1)
        if label not in (0, 1):
            continue
        vec = ex.process_raw_features(rec).reshape(1, -1)
        p = float(model.predict_proba(vec)[0, 1])     # P(malware)
        (malware_probs if label == 1 else benign_probs).append(p)

    assert len(benign_probs) > 50 and len(malware_probs) > 50   # enough samples to be meaningful
    # The mean malware score must clearly exceed the mean benign score.
    assert np.mean(malware_probs) > np.mean(benign_probs) + 0.3
    # And most benign files should fall below the malware files (rank separation).
    assert np.mean(malware_probs) > 0.7
    assert np.mean(benign_probs) < 0.3


# --------------------------------------------------------------------------
# Detector: honest behaviour with and without a model
# --------------------------------------------------------------------------
def test_detector_is_honest_when_unavailable(tmp_path):
    """With no model file, the detector reports unavailable -- never a fake score."""
    from ml.detector import EmberMalwareDetector
    det = EmberMalwareDetector(model_path=str(tmp_path / "does_not_exist.joblib"))
    assert det.available is False
    result = det.predict_bytes(b"arbitrary bytes")
    assert result.available is False
    assert result.malware_probability is None         # the key honesty guarantee
    assert result.is_malware is None
    assert result.error == "model_unavailable"


@pytest.mark.skipif(not os.path.exists(_MODEL_PATH), reason="trained model not present")
def test_detector_scores_bytes_when_available():
    """With a model present, the detector returns a probability in [0, 1]."""
    from ml.detector import EmberMalwareDetector
    det = EmberMalwareDetector(model_path=_MODEL_PATH)
    assert det.available is True
    result = det.predict_bytes(b"MZ" + b"\x00" * 2048)   # crude non-PE; must still score, not crash
    assert result.available is True
    assert 0.0 <= result.malware_probability <= 1.0
    assert isinstance(result.is_malware, bool)
