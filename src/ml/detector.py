"""
Inference-time malware detector for AntiV-AI.

This is the serve-time counterpart to scripts/train_ember.py. It loads the
gradient-boosted model trained on EMBER-2018 and scores arbitrary files using
the EXACT SAME feature extractor (src/ml/features.py) that produced the training
vectors. That shared code path is the whole point: it guarantees the model sees
the same kind of input at inference as it did during training.

Design principles
-----------------
* Honest degradation: if the model file is missing or a file cannot be parsed,
  the detector returns a result with `available=False` / `is_pe=False` and a
  `None` probability. It NEVER invents a number. Callers treat "unavailable" as
  "no ML signal" and fall back to other detection layers.
* Safety: extraction is pure static analysis (parsing bytes). Nothing is ever
  executed. Reads are size-capped so a huge upload cannot exhaust memory.
* Cheap to reuse: the model and extractor are loaded once and cached.
"""

import os                                   # path handling
import time                                 # per-scan timing
import hashlib                              # content hash for traceability
import logging                              # structured logging
from dataclasses import dataclass, asdict   # typed result object + easy JSON conversion
from typing import Optional                 # optional fields when ML is unavailable

import numpy as np                          # feature vector array

from .features import PEFeatureExtractor    # the shared train/serve extractor

logger = logging.getLogger(__name__)

# Default location of the trained model produced by scripts/train_ember.py.
_DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "models", "ember", "ember_model.joblib",
)

# Never read more than this many bytes from a single file into memory. PE files
# are typically well under this; the cap prevents a multi-GB upload from OOMing
# the process. (The byte-histogram/entropy features are computed over what we read.)
_MAX_READ_BYTES = 128 * 1024 * 1024         # 128 MiB


@dataclass
class MalwareScore:
    """Result of scoring one file. Designed to be safe to serialise to JSON."""

    available: bool                         # was a trained model loaded?
    sha256: str                             # content hash of the bytes scored
    malware_probability: Optional[float]    # 0.0 (benign) .. 1.0 (malware); None if unavailable
    is_malware: Optional[bool]              # probability >= operating threshold; None if unavailable
    threshold: float                        # operating threshold used for the boolean decision
    is_pe: bool                             # did the PE parser recognise a Windows executable?
    model_algo: str                         # which model produced the score
    elapsed_ms: float                       # wall-clock time for this scan
    error: Optional[str] = None             # populated only on failure

    def to_dict(self):
        # Convenience for API responses / logging.
        return asdict(self)


class EmberMalwareDetector:
    """Loads the EMBER-trained model and scores files via the shared extractor."""

    def __init__(self, model_path: str = _DEFAULT_MODEL_PATH):
        self.model_path = model_path        # where the trained model lives
        self._extractor = PEFeatureExtractor()   # 2,381-dim EMBER-v2 extractor (compiles regexes once)
        self._model = None                  # the sklearn/LightGBM estimator (lazy-loaded)
        self._algo = "unavailable"          # human-readable model name
        self._threshold = 0.5               # operating threshold; overwritten when the model loads
        self._loaded = False                # have we attempted to load yet?
        self._load_model()                  # try to load immediately (non-fatal if absent)

    # -- model loading -----------------------------------------------------
    def _load_model(self):
        """Attempt to load the trained model; record availability without raising."""
        self._loaded = True
        if not os.path.exists(self.model_path):
            # No model yet (e.g. training not run). Stay in honest "unavailable" mode.
            logger.warning("ML model not found at %s; detector running in unavailable mode. "
                           "Run scripts/train_ember.py to enable ML scoring.", self.model_path)
            return
        try:
            import joblib                            # local import so the module loads even w/o joblib
            bundle = joblib.load(self.model_path)     # dict saved by train_ember.py
            self._model = bundle["model"]             # the fitted estimator
            self._algo = bundle.get("algo", "unknown")
            self._threshold = float(bundle.get("operating_threshold", 0.5))
            logger.info("Loaded ML model '%s' (threshold=%.4f) from %s",
                        self._algo, self._threshold, self.model_path)
        except Exception as e:                        # corrupt/incompatible model -> stay unavailable
            self._model = None
            logger.error("Failed to load ML model from %s: %s", self.model_path, e)

    @property
    def available(self) -> bool:
        """True only when a usable model is loaded."""
        return self._model is not None

    # -- scoring -----------------------------------------------------------
    def predict_bytes(self, data: bytes) -> MalwareScore:
        """Score raw file bytes. Pure static analysis -- nothing is executed."""
        start = time.time()
        sha256 = hashlib.sha256(data).hexdigest()     # identify exactly what we scored

        # If no model is loaded, report unavailable honestly (no invented score).
        if not self.available:
            return MalwareScore(available=False, sha256=sha256, malware_probability=None,
                                is_malware=None, threshold=self._threshold, is_pe=False,
                                model_algo=self._algo, elapsed_ms=(time.time() - start) * 1000,
                                error="model_unavailable")

        try:
            # raw_features() also tells us whether a PE structure was parsed:
            # the 'general' group reports a non-zero virtual size only for real PEs.
            raw = self._extractor.raw_features(data)
            is_pe = bool(raw.get("general", {}).get("vsize", 0)) or bool(raw.get("section", {}).get("sections"))
            vec = self._extractor.process_raw_features(raw).reshape(1, -1)   # shape (1, 2381)

            # predict_proba returns P(benign), P(malware); we want the malware column.
            prob = float(self._model.predict_proba(vec)[0, 1])
            return MalwareScore(
                available=True, sha256=sha256, malware_probability=prob,
                is_malware=bool(prob >= self._threshold), threshold=self._threshold,
                is_pe=is_pe, model_algo=self._algo,
                elapsed_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            # Any extraction/inference failure -> unavailable result, never a crash.
            logger.error("ML scoring failed for %s: %s", sha256[:12], e)
            return MalwareScore(available=False, sha256=sha256, malware_probability=None,
                                is_malware=None, threshold=self._threshold, is_pe=False,
                                model_algo=self._algo, elapsed_ms=(time.time() - start) * 1000,
                                error=str(e))

    def predict_path(self, file_path: str) -> MalwareScore:
        """Score a file on disk (reads up to the size cap, then delegates to predict_bytes)."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(_MAX_READ_BYTES)        # size-capped read to bound memory
        except Exception as e:
            return MalwareScore(available=self.available, sha256="", malware_probability=None,
                                is_malware=None, threshold=self._threshold, is_pe=False,
                                model_algo=self._algo, elapsed_ms=0.0, error=f"read_error: {e}")
        return self.predict_bytes(data)


# A process-wide singleton so the model is loaded once and reused across requests.
# Importing this is cheap when the model is absent (it just logs a warning).
ember_detector = EmberMalwareDetector()
