from __future__ import print_function

import argparse
import io
import json
import sys

import stix2patterns.pattern

from stix2matcher.pattern_processor import MatchListener

# Example observed-data SDO.  This represents N observations, where N is
# the value of the "number_observed" property (in this case, 5).
#
# {
#   "type": "observed-data",
#   "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
#   "created": "2016-04-06T19:58:16.000Z",
#   "modified": "2016-04-06T19:58:16.000Z",
#   "first_observed": "2005-01-21T11:17:41Z",
#   "last_observed": "2005-01-21T11:22:41Z",
#   "number_observed": 5,
#   "objects": {
#     "0": {
#       "type": "file",
#       "hashes": {
#         "sha-256": "bf07a7fbb825fc0aae7bf4a1177b2b31fcf8a3feeaf7092761e18c859ee52"
#       }
#     },
#     "1": {
#       "type": "file",
#       "hashes": {
#         "md5": "22A0FB8F3879FB569F8A3FF65850A82E"
#       }
#     },
#     "2": {
#       "type": "file",
#       "hashes": {
#         "md5": "8D98A25E9D0662B1F4CA3BF22D6F53E9"
#       }
#     },
#     "3": {
#       "type": "file",
#       "hashes": {
#         "sha-256": "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb00"
#       },
#       "mime_type": "application/zip",
#       "extensions": {
#         "archive-ext": {
#           "contains_refs": [
#             "0",
#             "1",
#             "2"
#           ],
#           "version": "5.0"
#         }
#       }
#     }
#   }
# }


class Pattern(stix2patterns.pattern.Pattern):
    """
    Represents a pattern in a "compiled" form, for more efficient reuse.
    """

    def __init__(self, pattern_str):
        """
        Compile a pattern.

        :param pattern_str: The pattern to compile
        :raises stix2patterns.pattern.ParseException: If there is a parse error
        """
        super(Pattern, self).__init__(pattern_str)

    def match(self, observed_data_sdos, verbose=False):
        """
        Match this pattern against the given observations.  Returns matching
        SDOs.  The matcher can find many bindings; this function returns the
        SDOs corresponding to only the first binding found.

        :param observed_data_sdos: A list of observed-data SDOs, as a list of
            dicts.  STIX JSON should be parsed into native Python structures
            before calling this method.
        :param verbose: Whether to dump detailed info about matcher operation
        :return: Matching SDOs if the pattern matched; an empty list if it
            didn't match.
        :raises MatcherException: If an error occurs during matching
        """
        matcher = MatchListener(observed_data_sdos, verbose)
        self.walk(matcher)

        first_binding = next(matcher.matched(), [])
        matching_sdos = matcher.get_sdos_from_binding(first_binding)

        return matching_sdos


def match(pattern, observed_data_sdos, verbose=False):
    """
    Match the given pattern against the given observations.  Returns matching
    SDOs.  The matcher can find many bindings; this function returns the SDOs
    corresponding to only the first binding found.

    :param pattern: The STIX pattern
    :param observed_data_sdos: A list of observed-data SDOs, as a list of dicts.
        STIX JSON should be parsed into native Python structures before calling
        this function.
    :param verbose: Whether to dump detailed info about matcher operation
    :return: Matching SDOs if the pattern matched; an empty list if it didn't
        match.
    :raises stix2patterns.pattern.ParseException: If there is a parse error
    :raises MatcherException: If an error occurs during matching
    """

    compiled_pattern = Pattern(pattern)
    return compiled_pattern.match(observed_data_sdos, verbose)


def main():
    """
    Can be used as a command line tool to test pattern-matcher.
    """
    return_value = 0

    arg_parser = argparse.ArgumentParser(description="Match STIX Patterns to STIX Observed Data")
    arg_parser.add_argument(
        "-p",
        "--patterns",
        required=True,
        help="""
    Specify a file containing STIX Patterns, one per line.
    """,
    )
    arg_parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="""
    A file containing JSON list of STIX observed-data SDOs to match against.
    """,
    )
    arg_parser.add_argument(
        "-e",
        "--encoding",
        default="utf8",
        help="""
    Set encoding used for reading observation and pattern files.
    Must be an encoding name Python understands.  Default is utf8.
    """,
    )
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="""Be verbose""")
    arg_parser.add_argument(
        "-q",
        "--quiet",
        action="count",
        help="""
    Run quietly. One -q will only print out NO MATCH information. Two will
    produce no match-related output. This option does not affect the action
    of -v, and error information will still be displayed.""",
        default=0,
    )

    args = arg_parser.parse_args()

    try:
        with io.open(args.file, encoding=args.encoding) as json_in:
            observed_data_sdos = json.load(json_in)

        # Support single SDOs by converting to a list.
        if not isinstance(observed_data_sdos, list):
            observed_data_sdos = [observed_data_sdos]

        with io.open(args.patterns, encoding=args.encoding) as patterns_in:
            for pattern in patterns_in:
                pattern = pattern.strip()
                if not pattern:
                    continue  # skip blank lines
                if pattern[0] == u"#":
                    continue  # skip commented out lines
                escaped_pattern = pattern.encode("unicode_escape").decode("ascii")
                if match(pattern, observed_data_sdos, args.verbose):
                    if args.quiet < 1:
                        print(u"\nMATCH: ", escaped_pattern)
                else:
                    if args.quiet < 2:
                        print(u"\nNO MATCH: ", escaped_pattern)
                    return_value = 1
    except Exception:
        return_value = 2
        sys.excepthook(*sys.exc_info())
    return return_value


if __name__ == "__main__":
    sys.exit(main())
