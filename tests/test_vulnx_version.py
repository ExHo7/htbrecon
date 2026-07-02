"""Unit tests for vulnx client-side version-range filtering.

These cover the deterministic helpers only (no network, no AI):
``_cmp_version`` and ``_extract_range_verdict``.
"""

from __future__ import annotations

from htbrecon.scanners.vulnx import _cmp_version, _extract_range_verdict, _version_tuple


# ── _version_tuple / _cmp_version ──────────────────────────────────────────────

def test_version_tuple_parses_and_strips_v():
    assert _version_tuple("v1.4.0") == (1, 4, 0)
    assert _version_tuple("2.4.41") == (2, 4, 41)
    assert _version_tuple("2.4.41p1") == (2, 4, 41)  # stops at non-numeric tail
    assert _version_tuple("notaversion") == ()


def test_cmp_version_is_numeric_not_lexical():
    assert _cmp_version("2.4.9", "2.4.41") == -1   # 9 < 41 numerically
    assert _cmp_version("2.4.67", "2.4.41") == 1
    assert _cmp_version("2.4.41", "2.4.41") == 0
    assert _cmp_version("v1.4.0", "1.4.0") == 0     # v-prefix ignored
    assert _cmp_version("2.4", "2.4.0") == 0        # zero-padded


# ── _extract_range_verdict ─────────────────────────────────────────────────────

THROUGH = "Apache HTTP Server 2.4.17 through 2.4.67 contains a denial of service."

def test_through_range():
    assert _extract_range_verdict("2.4.41", THROUGH) == "in"
    assert _extract_range_verdict("2.4.70", THROUGH) == "out"
    assert _extract_range_verdict("2.4.10", THROUGH) == "out"   # below lower bound
    assert _extract_range_verdict("2.4.17", THROUGH) == "in"    # inclusive lower
    assert _extract_range_verdict("2.4.67", THROUGH) == "in"    # inclusive upper


def test_before_exclusive():
    desc = "The flaw affects all versions before 2.4.50."
    assert _extract_range_verdict("2.4.41", desc) == "in"
    assert _extract_range_verdict("2.4.55", desc) == "out"
    assert _extract_range_verdict("2.4.50", desc) == "out"      # exclusive bound


def test_and_earlier_inclusive():
    desc = "Version 1.4.0 and earlier are vulnerable."
    assert _extract_range_verdict("1.3.9", desc) == "in"
    assert _extract_range_verdict("1.4.0", desc) == "in"        # inclusive
    assert _extract_range_verdict("1.4.1", desc) == "out"


def test_remediation_fix_bound():
    desc = "A denial of service in the HTTP module."  # no version in desc
    rem = "Upgrade to a version later than 2.4.67 or the latest available version."
    assert _extract_range_verdict("2.4.41", desc, rem) == "in"
    assert _extract_range_verdict("2.4.68", desc, rem) == "out"


def test_exact_version_listed():
    desc = "Affected releases: 5.1.0, 5.2.0 and 5.3.0."
    assert _extract_range_verdict("5.2.0", desc) == "in"


def test_unknown_when_no_version_info():
    assert _extract_range_verdict("2.4.41", "A generic memory corruption issue.") == "unknown"


def test_unknown_when_no_detected_version():
    assert _extract_range_verdict("", THROUGH) == "unknown"
    assert _extract_range_verdict("notaversion", THROUGH) == "unknown"
