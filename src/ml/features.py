"""
PE feature extraction for AntiV-AI's machine-learning detector.

WHAT THIS FILE DOES
-------------------
It converts a Windows Portable-Executable (PE) file into a fixed-length vector
of 2,381 floating-point numbers that a machine-learning model can consume.

WHY IT MATTERS
--------------
A model can only be as good as the numbers you feed it, and it MUST see the
exact same kind of numbers during training and during real use. The previous
version of this project trained on random data and then, at inference time, fed
the model a vector that was almost entirely zeros (a "train-serve skew" bug), so
its "AI" output was meaningless. This module fixes that at the root: the very
same `process_raw_features()` code path is used both when we vectorise the
training dataset and when we score a freshly uploaded file.

LINEAGE / ATTRIBUTION
---------------------
The feature schema is a faithful, well-documented port of the EMBER project's
feature extractor (Hyrum Anderson & Phil Roth, "EMBER: An Open Dataset for
Training Static PE Malware Machine Learning Models", 2018;
https://github.com/elastic/ember, licensed Apache-2.0). Keeping the schema
identical to EMBER lets us train on EMBER's 1.1M-sample public dataset and then
score real files with the identical vectoriser.

Two adaptations were required for this codebase's environment:
  * NumPy >= 1.24 removed the `np.int` alias; we use `np.int64`/`int` instead.
  * LIEF 0.12.x renamed/relocated a few symbols; parsing is wrapped defensively
    so a malformed upload can never crash the API — it degrades to "no PE
    structure available" and the model still scores the byte-level features.

THE 2,381 FEATURES (9 groups)
-----------------------------
  ByteHistogram          256  normalised count of each byte value 0x00..0xff
  ByteEntropyHistogram   256  joint (byte, local-entropy) histogram
  StringExtractor        104  printable-string statistics (count, entropy, ...)
  GeneralFileInfo         10  size, #imports, #exports, has_signature, ...
  HeaderFileInfo          62  COFF + optional-header fields (hashed)
  SectionInfo            255  per-section size/entropy/vsize/flags (hashed)
  ImportsInfo           1280  imported libraries + functions (hashed)
  ExportsInfo            128  exported function names (hashed)
  DataDirectories         30  size + RVA of the 15 PE data directories
                        ----
                        2381
"""

import re                                   # regular expressions for string scanning of raw bytes
import json                                 # to load EMBER raw-feature records (one JSON object per line)
import os                                   # filesystem checks for the optional feature-subset file
import hashlib                              # to attach a SHA-256 to each raw-feature record
import numpy as np                          # all numeric work (histograms, vectors) is vectorised with NumPy

# The "hashing trick": map an unbounded set of strings (e.g. every possible
# imported function name) into a fixed number of buckets. This keeps the vector
# a constant width no matter how exotic a file's imports are.
from sklearn.feature_extraction import FeatureHasher

# LIEF is only needed for INFERENCE (parsing a real PE). Training reads EMBER's
# pre-extracted JSON, so we import LIEF lazily/defensively: if it is missing or a
# different version, training still works and inference degrades gracefully.
try:
    import lief                              # the PE parser used to derive structural features
    _LIEF_AVAILABLE = True                   # flag consulted by raw_features()
except Exception:                            # ImportError or any binary-load problem
    lief = None                              # sentinel so attribute access fails loudly if misused
    _LIEF_AVAILABLE = False


def _lief_version_flags():
    """Return (export_is_object, has_signatures_api) booleans for this LIEF build.

    LIEF changed two relevant APIs over time. We compute the behaviour once at
    import so the per-file extraction stays fast and never re-parses the version.
    """
    if not _LIEF_AVAILABLE:                  # no LIEF -> the flags are irrelevant
        return (True, True)                  # assume the modern API shape
    try:
        parts = str(lief.__version__).split(".")   # e.g. "0.12.3-" -> ["0","12","3-"]
        major = int(parts[0])                       # major version number
        minor = int(parts[1])                       # minor version number
    except Exception:                               # unexpected version string -> assume modern
        return (True, True)
    # exported_functions yields objects with a .name (LIEF >= 0.10), else raw strings
    export_is_object = (major > 0) or (major == 0 and minor >= 10)
    # the signature accessor became `has_signatures` (plural) in LIEF >= 0.11
    has_signatures_api = (major > 0) or (major == 0 and minor >= 11)
    return (export_is_object, has_signatures_api)


# Resolve the version-dependent behaviour a single time at import.
LIEF_EXPORT_OBJECT, LIEF_HAS_SIGNATURE = _lief_version_flags()


class FeatureType(object):
    """Base class for one group of features.

    Every group implements two methods:
      * raw_features()         -> a small JSON-serialisable dict/list (the
                                  "raw" representation that EMBER stores on disk)
      * process_raw_features() -> the fixed-width numeric vector for that group
    Splitting the two lets us vectorise EMBER's stored raw JSON without re-parsing
    any binaries, while the SAME process_raw_features() runs at inference time.
    """

    name = ""                                # unique key used in the raw-feature dict
    dim = 0                                  # number of numbers this group contributes

    def __repr__(self):
        # Helpful when printing an extractor, e.g. "imports(1280)".
        return "{}({})".format(self.name, self.dim)

    def raw_features(self, bytez, lief_binary):
        # Subclasses must override: build the raw representation from the file.
        raise NotImplementedError

    def process_raw_features(self, raw_obj):
        # Subclasses must override: turn the raw representation into numbers.
        raise NotImplementedError

    def feature_vector(self, bytez, lief_binary):
        # Convenience: extract raw features then immediately vectorise them.
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


class ByteHistogram(FeatureType):
    """Normalised histogram of byte values across the whole file (256 numbers)."""

    name = "histogram"                       # raw-feature dict key
    dim = 256                                # one bucket per possible byte value

    def raw_features(self, bytez, lief_binary):
        # Count how many times each byte value 0..255 occurs in the file.
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()               # store plain ints so it is JSON-serialisable

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)   # back to a float array
        total = counts.sum()                            # total number of bytes
        # Normalise to a probability distribution so file size does not dominate.
        # (Guard against an empty file producing a divide-by-zero -> NaN.)
        normalized = counts / total if total > 0 else counts
        return normalized


class ByteEntropyHistogram(FeatureType):
    """2-D (byte value, local entropy) histogram, flattened to 256 numbers.

    Loosely follows Saxe & Berlin (2015). It slides a window over the file,
    measures the local entropy of each window, and records the joint
    distribution of "how random is this region" vs "which byte values appear".
    Packed/encrypted malware shows a very different signature here than plain
    code or text.
    """

    name = "byteentropy"
    dim = 256                                # 16 entropy bins x 16 byte-value bins

    def __init__(self, step=1024, window=2048):
        self.window = window                 # size of each sliding window (bytes)
        self.step = step                     # how far the window advances each step

    def _entropy_bin_counts(self, block):
        # Coarsen each byte to its top 4 bits -> 16 possible values (16 bytes/bin).
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / self.window          # probability of each coarse value
        wh = np.where(c)[0]                              # indices that actually occurred (avoid log 0)
        # Shannon entropy of this window, scaled x2 because we halved the bit-depth.
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2
        Hbin = int(H * 2)                                # map entropy (0..8 bits) into 16 bins
        if Hbin == 16:                                   # entropy exactly 8.0 -> clamp into last bin
            Hbin = 15
        return Hbin, c

    def raw_features(self, bytez, lief_binary):
        # Accumulator: rows = entropy bin, cols = coarse byte value.
        output = np.zeros((16, 16), dtype=np.int64)      # np.int64 (np.int was removed in NumPy 1.24)
        a = np.frombuffer(bytez, dtype=np.uint8)         # file as an array of byte values
        if a.shape[0] < self.window:
            # File smaller than one window: treat the whole file as a single block.
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            # Build overlapping windows cheaply with a strided view (no data copy).
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:                         # accumulate every sampled window
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c
        return output.flatten().tolist()                 # flatten 16x16 -> 256 and make JSON-able

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        total = counts.sum()
        normalized = counts / total if total > 0 else counts   # normalise; guard empty input
        return normalized


class SectionInfo(FeatureType):
    """Per-section statistics, summarised with the hashing trick (255 numbers)."""

    name = "section"
    dim = 5 + 50 + 50 + 50 + 50 + 50         # 5 scalar counts + five 50-wide hashed blocks

    @staticmethod
    def _properties(s):
        # Convert LIEF's section-characteristic enums to short strings like "MEM_EXECUTE".
        try:
            return [str(c).split(".")[-1] for c in s.characteristics_lists]
        except Exception:
            return []                        # be defensive: a weird section must not crash us

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:              # no parseable PE -> empty section info
            return {"entry": "", "sections": []}

        # Identify the section that contains the entry point (or the first
        # executable section if the entry point is invalid). Wrapped in try/except
        # because malformed binaries routinely have bogus entry points.
        entry_section = ""
        try:
            section = lief_binary.section_from_rva(lief_binary.entrypoint - lief_binary.imagebase)
            entry_section = section.name if section is not None else ""
        except Exception:
            for s in lief_binary.sections:               # fall back: first executable section
                if "MEM_EXECUTE" in self._properties(s):
                    entry_section = s.name
                    break

        raw_obj = {"entry": entry_section}
        # Record name/size/entropy/virtual-size/flags for every section.
        raw_obj["sections"] = [{
            "name": s.name,
            "size": s.size,
            "entropy": s.entropy,
            "vsize": s.virtual_size,
            "props": self._properties(s),
        } for s in lief_binary.sections]
        return raw_obj

    def process_raw_features(self, raw_obj):
        sections = raw_obj["sections"]
        # Five interpretable scalar counts about the section table:
        general = [
            len(sections),                                                  # total number of sections
            sum(1 for s in sections if s["size"] == 0),                     # sections with zero raw size
            sum(1 for s in sections if s["name"] == ""),                    # sections with no name
            sum(1 for s in sections                                         # readable+executable sections
                if "MEM_READ" in s["props"] and "MEM_EXECUTE" in s["props"]),
            sum(1 for s in sections if "MEM_WRITE" in s["props"]),          # writable sections
        ]
        # Hash (section_name -> value) pairs into fixed 50-wide blocks so any
        # number of arbitrarily-named sections maps to a constant width.
        section_sizes = [(s["name"], s["size"]) for s in sections]
        section_sizes_hashed = FeatureHasher(50, input_type="pair").transform([section_sizes]).toarray()[0]
        section_entropy = [(s["name"], s["entropy"]) for s in sections]
        section_entropy_hashed = FeatureHasher(50, input_type="pair").transform([section_entropy]).toarray()[0]
        section_vsize = [(s["name"], s["vsize"]) for s in sections]
        section_vsize_hashed = FeatureHasher(50, input_type="pair").transform([section_vsize]).toarray()[0]
        # Hash the entry-point section name, and the flags of the entry section.
        # NOTE: the entry name is wrapped as [[name]] so it is hashed as ONE token.
        # (scikit-learn >= 1.4 rejects a bare string sample; the old EMBER code
        # accidentally hashed it character-by-character. We hash whole tokens and
        # use this same extractor for BOTH training and inference, so the pipeline
        # is internally consistent and never touches EMBER's pre-vectorised .dat.)
        entry_name_hashed = FeatureHasher(50, input_type="string").transform([[raw_obj["entry"]]]).toarray()[0]
        characteristics = [p for s in sections for p in s["props"] if s["name"] == raw_obj["entry"]]
        characteristics_hashed = FeatureHasher(50, input_type="string").transform([characteristics]).toarray()[0]
        # Concatenate the 5 scalars + five 50-wide blocks = 255 numbers.
        return np.hstack([
            general, section_sizes_hashed, section_entropy_hashed,
            section_vsize_hashed, entry_name_hashed, characteristics_hashed,
        ]).astype(np.float32)


class ImportsInfo(FeatureType):
    """Imported libraries (256) + fully-qualified imported functions (1024)."""

    name = "imports"
    dim = 1280

    def raw_features(self, bytez, lief_binary):
        imports = {}                         # {library_name: [function_names...]}
        if lief_binary is None:
            return imports
        for lib in lief_binary.imports:      # iterate the import address table
            if lib.name not in imports:
                imports[lib.name] = []       # libs can be listed twice; extend rather than overwrite
            for entry in lib.entries:
                if entry.is_ordinal:                         # imported by ordinal number
                    imports[lib.name].append("ordinal" + str(entry.ordinal))
                else:                                        # imported by name (clip very long names)
                    imports[lib.name].append(entry.name[:10000])
        return imports

    def process_raw_features(self, raw_obj):
        # Hash the set of unique (lower-cased) library names into 256 buckets.
        libraries = list(set([l.lower() for l in raw_obj.keys()]))
        libraries_hashed = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]
        # Hash strings like "kernel32.dll:CreateFileMappingA" into 1024 buckets.
        imports = [lib.lower() + ":" + e for lib, elist in raw_obj.items() for e in elist]
        imports_hashed = FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0]
        return np.hstack([libraries_hashed, imports_hashed]).astype(np.float32)


class ExportsInfo(FeatureType):
    """Exported function names, hashed into 128 buckets."""

    name = "exports"
    dim = 128

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return []
        if LIEF_EXPORT_OBJECT:               # modern LIEF: each export has a .name attribute
            return [export.name[:10000] for export in lief_binary.exported_functions]
        # very old LIEF (<= 0.9): exported_functions yields plain strings
        return [export[:10000] for export in lief_binary.exported_functions]

    def process_raw_features(self, raw_obj):
        exports_hashed = FeatureHasher(128, input_type="string").transform([raw_obj]).toarray()[0]
        return exports_hashed.astype(np.float32)


class GeneralFileInfo(FeatureType):
    """Ten high-level facts about the file (size, #imports, has_signature, ...)."""

    name = "general"
    dim = 10

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:              # non-PE / unparseable: only the byte size is known
            return {"size": len(bytez), "vsize": 0, "has_debug": 0, "exports": 0,
                    "imports": 0, "has_relocations": 0, "has_resources": 0,
                    "has_signature": 0, "has_tls": 0, "symbols": 0}
        # `has_signatures` (plural) on newer LIEF, `has_signature` on older builds.
        has_sig = int(lief_binary.has_signatures) if LIEF_HAS_SIGNATURE else int(lief_binary.has_signature)
        return {
            "size": len(bytez),                                  # on-disk size in bytes
            "vsize": lief_binary.virtual_size,                   # size once mapped into memory
            "has_debug": int(lief_binary.has_debug),             # contains a debug directory?
            "exports": len(lief_binary.exported_functions),      # number of exported functions
            "imports": len(lief_binary.imported_functions),      # number of imported functions
            "has_relocations": int(lief_binary.has_relocations), # contains relocations?
            "has_resources": int(lief_binary.has_resources),     # contains a resource section?
            "has_signature": has_sig,                            # Authenticode-signed?
            "has_tls": int(lief_binary.has_tls),                 # uses thread-local storage?
            "symbols": len(lief_binary.symbols),                 # number of COFF symbols
        }

    def process_raw_features(self, raw_obj):
        # Emit the ten values in a fixed order.
        return np.asarray([
            raw_obj["size"], raw_obj["vsize"], raw_obj["has_debug"], raw_obj["exports"],
            raw_obj["imports"], raw_obj["has_relocations"], raw_obj["has_resources"],
            raw_obj["has_signature"], raw_obj["has_tls"], raw_obj["symbols"],
        ], dtype=np.float32)


class HeaderFileInfo(FeatureType):
    """COFF header + optional header fields, with categorical values hashed (62)."""

    name = "header"
    dim = 62

    def raw_features(self, bytez, lief_binary):
        # Start with safe defaults so a non-PE produces a valid (all-zero-ish) record.
        raw_obj = {"coff": {"timestamp": 0, "machine": "", "characteristics": []},
                   "optional": {"subsystem": "", "dll_characteristics": [], "magic": "",
                                "major_image_version": 0, "minor_image_version": 0,
                                "major_linker_version": 0, "minor_linker_version": 0,
                                "major_operating_system_version": 0, "minor_operating_system_version": 0,
                                "major_subsystem_version": 0, "minor_subsystem_version": 0,
                                "sizeof_code": 0, "sizeof_headers": 0, "sizeof_heap_commit": 0}}
        if lief_binary is None:
            return raw_obj
        h = lief_binary.header                       # COFF file header
        o = lief_binary.optional_header              # PE optional header
        raw_obj["coff"]["timestamp"] = h.time_date_stamps                       # link timestamp
        raw_obj["coff"]["machine"] = str(h.machine).split(".")[-1]              # target CPU (e.g. AMD64)
        raw_obj["coff"]["characteristics"] = [str(c).split(".")[-1] for c in h.characteristics_list]
        raw_obj["optional"]["subsystem"] = str(o.subsystem).split(".")[-1]      # GUI / console / driver
        raw_obj["optional"]["dll_characteristics"] = [str(c).split(".")[-1] for c in o.dll_characteristics_lists]
        raw_obj["optional"]["magic"] = str(o.magic).split(".")[-1]              # PE32 vs PE32+
        raw_obj["optional"]["major_image_version"] = o.major_image_version
        raw_obj["optional"]["minor_image_version"] = o.minor_image_version
        raw_obj["optional"]["major_linker_version"] = o.major_linker_version
        raw_obj["optional"]["minor_linker_version"] = o.minor_linker_version
        raw_obj["optional"]["major_operating_system_version"] = o.major_operating_system_version
        raw_obj["optional"]["minor_operating_system_version"] = o.minor_operating_system_version
        raw_obj["optional"]["major_subsystem_version"] = o.major_subsystem_version
        raw_obj["optional"]["minor_subsystem_version"] = o.minor_subsystem_version
        raw_obj["optional"]["sizeof_code"] = o.sizeof_code
        raw_obj["optional"]["sizeof_headers"] = o.sizeof_headers
        raw_obj["optional"]["sizeof_heap_commit"] = o.sizeof_heap_commit
        return raw_obj

    def process_raw_features(self, raw_obj):
        # Numeric fields go in directly; categorical fields are hashed into 10-wide blocks.
        return np.hstack([
            raw_obj["coff"]["timestamp"],
            FeatureHasher(10, input_type="string").transform([[raw_obj["coff"]["machine"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj["coff"]["characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj["optional"]["subsystem"]]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj["optional"]["dll_characteristics"]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj["optional"]["magic"]]]).toarray()[0],
            raw_obj["optional"]["major_image_version"],
            raw_obj["optional"]["minor_image_version"],
            raw_obj["optional"]["major_linker_version"],
            raw_obj["optional"]["minor_linker_version"],
            raw_obj["optional"]["major_operating_system_version"],
            raw_obj["optional"]["minor_operating_system_version"],
            raw_obj["optional"]["major_subsystem_version"],
            raw_obj["optional"]["minor_subsystem_version"],
            raw_obj["optional"]["sizeof_code"],
            raw_obj["optional"]["sizeof_headers"],
            raw_obj["optional"]["sizeof_heap_commit"],
        ]).astype(np.float32)


class StringExtractor(FeatureType):
    """Statistics about printable ASCII strings inside the file (104 numbers)."""

    name = "strings"
    dim = 1 + 1 + 1 + 96 + 1 + 1 + 1 + 1 + 1   # counts + 96-wide char distribution + flags

    def __init__(self):
        self._allstrings = re.compile(b"[\x20-\x7f]{5,}")   # runs of >=5 printable chars
        self._paths = re.compile(b"c:\\\\", re.IGNORECASE)  # evidence of Windows file paths
        self._urls = re.compile(b"https?://", re.IGNORECASE)# evidence of URLs
        self._registry = re.compile(b"HKEY_")               # evidence of registry keys
        self._mz = re.compile(b"MZ")                         # embedded PE header (dropper behaviour)

    def raw_features(self, bytez, lief_binary):
        allstrings = self._allstrings.findall(bytez)         # every printable string in the file
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)         # average string length
            # Map each printable char to 0..95 and build a distribution histogram.
            as_shifted_string = [b - ord(b"\x20") for b in b"".join(allstrings)]
            c = np.bincount(as_shifted_string, minlength=96)
            csum = c.sum()
            p = c.astype(np.float32) / csum
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh]))              # entropy of the character distribution
        else:                                                # file has no printable strings
            avlength = 0
            c = np.zeros((96,), dtype=np.float32)
            H = 0
            csum = 0
        return {
            "numstrings": len(allstrings),                   # how many strings
            "avlength": avlength,                            # average length
            "printabledist": c.tolist(),                     # raw 96-bin char histogram
            "printables": int(csum),                         # total printable chars
            "entropy": float(H),                             # char-distribution entropy
            "paths": len(self._paths.findall(bytez)),        # # of "C:\" occurrences
            "urls": len(self._urls.findall(bytez)),          # # of URL occurrences
            "registry": len(self._registry.findall(bytez)),  # # of "HKEY_" occurrences
            "MZ": len(self._mz.findall(bytez)),              # # of embedded "MZ" headers
        }

    def process_raw_features(self, raw_obj):
        # Normalise the char histogram by the total printable count (guard divide-by-zero).
        hist_divisor = float(raw_obj["printables"]) if raw_obj["printables"] > 0 else 1.0
        return np.hstack([
            raw_obj["numstrings"], raw_obj["avlength"], raw_obj["printables"],
            np.asarray(raw_obj["printabledist"]) / hist_divisor,
            raw_obj["entropy"], raw_obj["paths"], raw_obj["urls"],
            raw_obj["registry"], raw_obj["MZ"],
        ]).astype(np.float32)


class DataDirectories(FeatureType):
    """Size + virtual address (RVA) of the 15 PE data directories (30 numbers)."""

    name = "datadirectories"
    dim = 15 * 2

    def __init__(self):
        # The canonical order of the 15 directories (only the first 15 are used).
        self._name_order = [
            "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "CERTIFICATE_TABLE",
            "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE",
            "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER",
        ]

    def raw_features(self, bytez, lief_binary):
        output = []
        if lief_binary is None:
            return output
        for data_directory in lief_binary.data_directories:
            output.append({
                "name": str(data_directory.type).replace("DATA_DIRECTORY.", ""),
                "size": data_directory.size,                 # bytes occupied by this directory
                "virtual_address": data_directory.rva,       # where it lives in the mapped image
            })
        return output

    def process_raw_features(self, raw_obj):
        features = np.zeros(2 * len(self._name_order), dtype=np.float32)
        # For each of the first 15 directories, store [size, rva].
        for i in range(len(self._name_order)):
            if i < len(raw_obj):
                features[2 * i] = raw_obj[i]["size"]
                features[2 * i + 1] = raw_obj[i]["virtual_address"]
        return features


class PEFeatureExtractor(object):
    """Extract the full 2,381-dimensional EMBER-v2 feature vector from a PE file.

    Usage at inference time:
        extractor = PEFeatureExtractor()
        vec = extractor.feature_vector(file_bytes)   # -> np.float32 array, shape (2381,)

    Usage when vectorising EMBER's stored raw JSON (training):
        vec = extractor.process_raw_features(json.loads(line))
    """

    def __init__(self, feature_version=2, print_feature_warning=False, features_file=""):
        # The 8 base feature groups, in the exact order EMBER concatenates them.
        features = {
            "ByteHistogram": ByteHistogram(),
            "ByteEntropyHistogram": ByteEntropyHistogram(),
            "StringExtractor": StringExtractor(),
            "GeneralFileInfo": GeneralFileInfo(),
            "HeaderFileInfo": HeaderFileInfo(),
            "SectionInfo": SectionInfo(),
            "ImportsInfo": ImportsInfo(),
            "ExportsInfo": ExportsInfo(),
        }
        # An optional JSON file can select a subset of groups (not used by default).
        if features_file and os.path.exists(features_file):
            with open(features_file, encoding="utf8") as f:
                x = json.load(f)
                self.features = [features[k] for k in x["features"] if k in features]
        else:
            self.features = list(features.values())

        # Feature version 2 (EMBER-2018) adds the DataDirectories group.
        if feature_version == 2:
            self.features.append(DataDirectories())
        elif feature_version != 1:
            raise ValueError("EMBER feature version must be 1 or 2, not %r" % feature_version)

        if print_feature_warning and _LIEF_AVAILABLE and not str(lief.__version__).startswith("0.9"):
            # EMBER-2018 vectors were computed with LIEF 0.9.0; newer LIEF can differ
            # by a hair on a handful of files. We surface this only when asked.
            print("NOTE: EMBER-v2 features were computed with LIEF 0.9.0; this build is "
                  "%s, so a small number of files may vectorise slightly differently."
                  % lief.__version__)

        # Total width = sum of every group's dimension (2,381 for version 2).
        self.dim = sum(fe.dim for fe in self.features)

    def raw_features(self, bytez):
        """Parse `bytez` (a PE file as raw bytes) into EMBER's raw-feature dict."""
        lief_binary = None
        if _LIEF_AVAILABLE:
            try:
                # LIEF 0.12 accepts a list of byte values; this never executes the file.
                lief_binary = lief.PE.parse(list(bytez))
            except Exception:
                # Malformed / non-PE input: keep going with byte-only features.
                lief_binary = None
        # Attach a content hash, then each group's raw representation, keyed by name.
        out = {"sha256": hashlib.sha256(bytez).hexdigest()}
        out.update({fe.name: fe.raw_features(bytez, lief_binary) for fe in self.features})
        return out

    def process_raw_features(self, raw_obj):
        """Turn a raw-feature dict (from raw_features() OR EMBER JSON) into a vector."""
        # Vectorise each group and concatenate in the fixed group order.
        feature_vectors = [fe.process_raw_features(raw_obj[fe.name]) for fe in self.features]
        return np.hstack(feature_vectors).astype(np.float32)

    def feature_vector(self, bytez):
        """One-shot: raw bytes -> final 2,381-dim numeric vector."""
        return self.process_raw_features(self.raw_features(bytez))
