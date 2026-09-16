import pytest

from a2a_compliance.wire import canonical


def test_object_keys_sort_by_utf16_code_unit():
    assert canonical.canonicalize({"b": 1, "a": 2, "é": 3, "A": 4}) == '{"A":4,"a":2,"b":1,"é":3}'


def test_nested_object_and_array_order_preserved_values_sorted():
    value = {"a": [1, 2, {"z": 1, "y": 2}], "b": None, "c": True, "d": "hi\"there\n"}
    assert canonical.canonicalize(value) == '{"a":[1,2,{"y":2,"z":1}],"b":null,"c":true,"d":"hi\\"there\\n"}'


def test_no_spaces_no_trailing_content():
    assert canonical.canonicalize({"x": 1, "y": [1, 2, 3]}) == '{"x":1,"y":[1,2,3]}'


def test_non_ascii_strings_are_not_uXXXX_escaped():
    assert canonical.canonicalize("café") == '"café"'


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0"), (-1, "-1"), (1, "1"),
        (0.0, "0"), (-0.0, "0"), (1.5, "1.5"), (100.0, "100"),
        (1e21, "1e+21"), (1e-7, "1e-7"), (1.1, "1.1"),
        (123456789012345680000.0, "123456789012345680000"),
        (-1e100, "-1e+100"), (3.0, "3"), (-2.5, "-2.5"),
    ],
)
def test_number_formatting_matches_ecma262_number_tostring(value, expected):
    assert canonical.canonicalize(value) == expected


def test_nan_and_infinity_are_rejected():
    with pytest.raises(ValueError):
        canonical.canonicalize(float("nan"))
    with pytest.raises(ValueError):
        canonical.canonicalize(float("inf"))


def test_digest_hex_is_sha256_of_canonical_bytes():
    import hashlib
    value = {"a": 1}
    expected = hashlib.sha256(canonical.canonicalize(value).encode("utf-8")).hexdigest()
    assert canonical.digest_hex(value) == expected
    assert len(canonical.digest_hex(value)) == 64


def test_subject_digest_excludes_signature_and_itself():
    base = {"a": 1, "signature": "sig-1"}
    d1 = canonical.subject_digest(base)
    with_digest = {**base, "subject_digest": d1}
    # recomputing on an object that already carries subject_digest must give
    # the SAME value (subject_digest cannot be part of its own input)
    assert canonical.subject_digest(with_digest) == d1
    # changing only signature must not change subject_digest
    assert canonical.subject_digest({**base, "signature": "sig-2"}) == d1
    # changing a real field must change it
    assert canonical.subject_digest({**base, "a": 2}) != d1


def test_key_order_is_independent_of_input_order():
    a = {"z": 1, "a": 2, "m": 3}
    b = {"m": 3, "z": 1, "a": 2}
    assert canonical.canonicalize(a) == canonical.canonicalize(b)


def test_surrogate_pair_key_sorts_by_utf16_units():
    # U+FFFF (BMP, single code unit 0xFFFF) must sort BEFORE any astral
    # character (which starts with a high surrogate >= 0xD800 < 0xFFFF is
    # false -- astral chars encode as a high surrogate 0xD800-0xDBFF then a
    # low surrogate; 0xD800 < 0xFFFF, so U+10000 sorts BEFORE U+FFFF under
    # UTF-16 code-unit order even though its codepoint is larger).
    astral = "\U00010000"  # first astral codepoint -> surrogate units (0xD800, 0xDC00)
    bmp_high = "￿"
    value = {bmp_high: 1, astral: 2}
    out = canonical.canonicalize(value)
    assert out.index(canonical.canonicalize(astral)) < out.index(canonical.canonicalize(bmp_high))
