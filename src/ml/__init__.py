"""
AntiV-AI machine-learning package.

This package contains the *real* malware-detection pipeline:

    features.py  -> PEFeatureExtractor: turns a PE file (or EMBER raw-feature
                    record) into a fixed-length 2,381-dimensional numeric vector.
                    The SAME code path is used at training time and at inference
                    time, which is what prevents "train-serve skew" (the bug that
                    made the previous synthetic model non-functional).

    detector.py  -> EmberMalwareDetector: loads a trained gradient-boosted model
                    plus the extractor and scores arbitrary files. It degrades
                    honestly (reports "unavailable") instead of inventing a score
                    when the model or a parser is missing.

The feature design is a faithful port of the EMBER project
(https://github.com/elastic/ember, Apache-2.0), modernised for NumPy >= 1.24
and LIEF 0.12.x. See src/ml/features.py for the full attribution.
"""

# Re-export the two public entry points so callers can simply do
#   `from ml.features import PEFeatureExtractor` or `from ml import PEFeatureExtractor`.
from .features import PEFeatureExtractor  # noqa: F401  (re-exported on purpose)

__all__ = ["PEFeatureExtractor"]
