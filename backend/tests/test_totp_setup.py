import base64
import pytest
from icp import totp

KEY = b"12345678901234567890"                      # RFC 6238 seed
B32 = base64.b32encode(KEY).decode()


def test_bare_key_with_spaces_and_lowercase():
    cfg = totp.parse_setup(" ".join(B32.lower()[i:i + 4] for i in range(0, len(B32), 4)))
    assert cfg["secret"] == KEY and cfg["digits"] == 6 and cfg["period"] == 30
    assert "originalURL" not in cfg


def test_otpauth_link_keeps_issuer_account_and_url():
    url = f"otpauth://totp/Example%20Co:alex%40example.com?secret={B32}&issuer=Example%20Co&digits=8&period=60&algorithm=SHA256"
    cfg = totp.parse_setup(url)
    assert cfg["secret"] == KEY
    assert (cfg["digits"], cfg["period"], cfg["algorithm"]) == (8, 60, 1)
    assert cfg["issuer"] == "Example Co" and cfg["accountName"] == "alex@example.com"
    assert cfg["originalURL"] == url


def test_code_from_parsed_setup_matches_rfc_vector():
    cfg = totp.parse_setup(B32)
    assert totp.code(cfg["secret"], digits=8, at=59) == "94287082"


@pytest.mark.parametrize("bad", ["", "otpauth://hotp/x?secret=" + B32, "not a key!", "AAAA",
                                 "otpauth://totp/x?secret=" + B32 + "&algorithm=MD5"])
def test_rejects(bad):
    with pytest.raises(totp.SetupError):
        totp.parse_setup(bad)
