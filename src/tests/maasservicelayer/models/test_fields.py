# Copyright 2025 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

import pytest

from maasservicelayer.models.fields import GpgKey

# A minimal valid ASCII-armored PGP public key block.
VALID_GPG_KEY = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.1.5

mQINBFXVlyMBEACqM3iz2EGJE0iE3/AAbNCnbBB25m3AWaSxJk+GJfkAAYWGqAKiuWceCcet
dNKNTKd8frSZFsRB7IceZr0u5sWpSYur6uoMNHzS8Y5cGdyAVrnEZtbdak652x13jlX7nrcE
9g//lD0w254XW1Loyy5YOGWfUmJkGImndFWtkqd1J7SCVMMW5l/nS4LwsOx/wTxL5m/cFQLi
67JyJGqszKXS88oHT1YFBWPyl1VcXifFwecH/32fRr6WGpEAaxGF4dO45WGvJIQs2yiT5f9h
=QeWQ
-----END PGP PUBLIC KEY BLOCK-----"""


class TestGpgKey:
    def test_empty_string_is_accepted(self):
        key = GpgKey("")
        assert key == ""

    def test_none_becomes_empty_string(self):
        key = GpgKey.validate(None)
        assert key == ""

    def test_valid_ascii_armored_key_is_accepted(self):
        key = GpgKey(VALID_GPG_KEY)
        assert key == VALID_GPG_KEY

    def test_valid_key_with_surrounding_whitespace_is_accepted(self):
        padded = f"\n{VALID_GPG_KEY}\n"
        key = GpgKey(padded)
        assert key == padded

    @pytest.mark.parametrize(
        "invalid_value",
        [
            "whatever",
            "not-a-key",
            "BEGIN PGP PUBLIC KEY BLOCK",  # missing dashes
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\ndata\n-----END PGP PRIVATE KEY BLOCK-----",
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",  # missing end marker
        ],
    )
    def test_invalid_key_raises_value_error(self, invalid_value: str):
        with pytest.raises(ValueError, match="not a valid GPG public key"):
            GpgKey(invalid_value)
