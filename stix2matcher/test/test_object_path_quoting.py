import pytest

from stix2matcher.matcher import match, MatcherException

_observations = [
    {
        "type": "observed-data",
        "first_observed": "2004-10-11T21:44:58Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": u"some-type",
                "has-hyphen": 1,
                "has.dot": 2,
                "has-hyphen.dot": 3
            }
        }
    },
]


@pytest.mark.parametrize("pattern", [
    "[some-type:'has-hyphen' = 1]",
    "[some-type:'has.dot' = 2]",
    "[some-type:'has-hyphen.dot' = 3]"
])
def test_quoting(pattern):
    assert match(pattern, _observations)


@pytest.mark.parametrize("pattern", [
    "[some-type:needs-quotes = 1]"
])
def test_quoting_error(pattern):
    with pytest.raises(MatcherException):
        match(pattern, _observations)