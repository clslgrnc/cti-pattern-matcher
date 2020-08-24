import base64
import binascii
import datetime
import io
import operator
import socket
import struct

import antlr4
import dateutil.tz
import six
from stix2patterns.grammars.STIXPatternParser import STIXPatternParser

from stix2matcher.exception import (
    MatcherException,
    MatcherInternalError,
)


# Coercers from strings (what all token values are) to python types.
# Set and regex literals are not handled here; they're a different beast...
_TOKEN_TYPE_COERCERS = {
    STIXPatternParser.IntPosLiteral: int,
    STIXPatternParser.IntNegLiteral: int,
    STIXPatternParser.StringLiteral: lambda s: s[1:-1].replace(u"\\'", u"'").replace(u"\\\\", u"\\"),
    STIXPatternParser.BoolLiteral: lambda s: s.lower() == u"true",
    STIXPatternParser.FloatPosLiteral: float,
    STIXPatternParser.FloatNegLiteral: float,
    STIXPatternParser.BinaryLiteral: lambda s: base64.standard_b64decode(s[2:-1]),
    STIXPatternParser.HexLiteral: lambda s: binascii.a2b_hex(s[2:-1]),
    STIXPatternParser.TimestampLiteral: lambda t: _str_to_datetime(t[2:-1]),
}


# Map python types to 2-arg equality functions.  The functions must return
# True if equal, False otherwise.
#
# This table may be treated symmetrically via _get_table_symmetric() below.
# (I only added half the entries since I plan to use that.)  And of course,
# that means all the functions in the table must be insensitive to the order
# of types of their arguments.
#
# Where I use python operators, python's mixed-type comparison rules are
# in effect, e.g. conversion of operands to a common type.


def _bin_str_equals(val1, val2):
    # Figure out which arg is the binary one, and which is the string...
    if isinstance(val1, six.text_type):
        str_val = val1
        bin_val = val2
    else:
        str_val = val2
        bin_val = val1

    # Comparison is only allowed if all the string codepoints are < 256.
    cmp_allowed = all(ord(c) < 256 for c in str_val)

    if not cmp_allowed:
        # Per spec, this results in not-equal.
        return False

    str_as_bin = bytearray(ord(c) for c in str_val)
    return str_as_bin == bin_val


_COMPARE_EQ_FUNCS = {
    int: {
        int: operator.eq,
        float: operator.eq
    },
    float: {
        float: operator.eq
    },
    six.binary_type: {
        six.binary_type: operator.eq,
        six.text_type: _bin_str_equals
    },
    six.text_type: {
        six.text_type: operator.eq
    },
    bool: {
        bool: operator.eq
    },
    datetime.datetime: {
        datetime.datetime: operator.eq
    }
}


# Similar for <, >, etc comparisons.  These functions should return <0 if
# first arg is less than second; 0 if equal, >0 if first arg is greater.
#
# This table may be treated symmetrically via _get_table_symmetric() below.
# (I only added half the entries since I plan to use that.)  And of course,
# that means all the functions in the table must be insensitive to the order
# of types of their arguments.
#
# Where I use python operators, python's mixed-type comparison rules are
# in effect, e.g. conversion of operands to a common type.
#
# cmp() was removed in Python 3. See
# https://docs.python.org/3.0/whatsnew/3.0.html#ordering-comparisons
def _cmp(a, b):
    return (a > b) - (a < b)


def _bin_str_compare(val1, val2):
    """
    Does string/binary comparison as described in the spec.  Raises an
    exception if the string is unsuitable for comparison.  The spec says
    the result must be "false", but order comparators can't return true or
    false.  Their purpose is to compute an ordering: less, equal, or greater.
    So I have to use an exception.

    One of the args must be of unicode type, the other must be a binary type
    (bytes/str, bytearray, etc).
    """

    # Figure out which arg is the binary one, and which is the string...
    if isinstance(val1, six.text_type):
        str_val = val1
        str_was_first = True
    else:
        str_val = val2
        str_was_first = False

    # Comparison is only allowed if all the string codepoints are < 256.
    cmp_allowed = all(ord(c) < 256 for c in str_val)

    if not cmp_allowed:
        raise ValueError(u"Can't compare to binary: " + str_val)

    str_as_bin = bytearray(ord(c) for c in str_val)

    if str_was_first:
        return _cmp(str_as_bin, val2)
    else:
        return _cmp(val1, str_as_bin)


_COMPARE_ORDER_FUNCS = {
    int: {
        int: _cmp,
        float: _cmp
    },
    float: {
        float: _cmp
    },
    six.binary_type: {
        six.binary_type: _cmp,
        six.text_type: _bin_str_compare
    },
    six.text_type: {
        six.text_type: _cmp
    },
    datetime.datetime: {
        datetime.datetime: _cmp
    }
}


def _get_table_symmetric(table, val1, val2):
    """
    Gets an operator from a table according to the given types.  This
    gives the illusion of a symmetric matrix, e.g. if tbl[a][b] doesn't exist,
    tbl[b][a] is automatically tried.  That means you only have to fill out
    half of the given table.  (The "table" is a nested dict.)
    """
    tmp = table.get(val1)
    if tmp is None:
        # table[val1] is missing; try table[val2]
        tmp = table.get(val2)
        if tmp is None:
            return None
        return tmp.get(val1)
    else:
        # table[val1] is there.  But if table[val1][val2] is missing,
        # we still gotta try it the other way.
        tmp = tmp.get(val2)
        if tmp is not None:
            return tmp

        # gotta try table[val2][val1] now.
        tmp = table.get(val2)
        if tmp is None:
            return None
        return tmp.get(val1)


def _process_prop_suffix(prop_name, value):
    """
    Some JSON properties have suffixes indicating the type of the value.  This
    will translate the json value into a Python type with the proper semantics,
    so that subsequent property tests will work properly.

    :param prop_name: The JSON property name
    :param value: The JSON property value
    :return: If key is a specially suffixed property name, an instance of an
        appropriate python type.  Otherwise, value itself is returned.
    """

    if prop_name.endswith(u"_hex"):
        # binary type, expressed as hex
        value = binascii.a2b_hex(value)
    elif prop_name.endswith(u"_bin"):
        # binary type, expressed as base64
        value = base64.standard_b64decode(value)

    return value


def _step_into_objs(objs, step):
    """
    'objs' is a list of Cyber Observable object (sub)structures.  'step'
    describes a step into the structure, relative to the top level: if an int,
    we assume the top level is a list, and the int is a list index.  If a
    string, assume the top level is a dict, and the string is a key.  If a
    structure is such that the step can't be taken (e.g. the dict doesn't have
    the particular key), filter the value from the list.

    This will also automatically convert values of specially suffixed
    properties into the proper type.  See _process_prop_suffix().

    :return: A new list containing the "stepped-into" structures, minus
       any structures which couldn't be stepped into.
    """

    stepped_cyber_obs_objs = []
    if isinstance(step, int):
        for obj in objs:
            if isinstance(obj, list) and 0 <= step < len(obj):
                stepped_cyber_obs_objs.append(obj[step])
            # can't index non-lists
    elif isinstance(step, six.text_type):
        for obj in objs:
            if isinstance(obj, dict) and step in obj:
                processed_value = _process_prop_suffix(step, obj[step])
                stepped_cyber_obs_objs.append(processed_value)
            # can't do key lookup in non-dicts

    else:
        raise MatcherInternalError(
            u"Unsupported step type: {}".format(type(step)))

    return stepped_cyber_obs_objs


def _step_filter_observations(observations, step):
    """
    A helper for the listener.  Given a particular structure in 'observations'
    (see exitObjectType(), exitFirstPathComponent()), representing a set of
    observations and partial path stepping state, do a pass over all the
    observations, attempting to take the given step on all of their Cyber
    Observable objects (or partial Cyber Observable object structures).

    :return: a filtered observation map: it includes those for which at
      least one contained Cyber Observable object was successfully stepped.  If none
      of an observation's Cyber Observable objects could be successfully stepped,
      the observation is dropped.
    """

    filtered_obs_map = {}
    for obs_idx, cyber_obs_obj_map in six.iteritems(observations):
        filtered_cyber_obs_obj_map = {}
        for cyber_obs_obj_id, cyber_obs_objs in six.iteritems(cyber_obs_obj_map):
            filtered_cyber_obs_obj_list = _step_into_objs(cyber_obs_objs, step)

            if len(filtered_cyber_obs_obj_list) > 0:
                filtered_cyber_obs_obj_map[cyber_obs_obj_id] = filtered_cyber_obs_obj_list

        if len(filtered_cyber_obs_obj_map) > 0:
            filtered_obs_map[obs_idx] = filtered_cyber_obs_obj_map

    return filtered_obs_map


def _step_filter_observations_index_star(observations):
    """
    Does an index "star" step, i.e. "[*]".  This will pull out all elements of
    the list as if they were parts of separate Cyber Observable objects, which
    has the desired effect for matching: if any list elements match the
    remainder of the pattern, they are selected for the subsequent property
    test.  As usual, non-lists at this point are dropped, and observations for
    whom all Cyber Observable object (sub)structure was dropped, are also
    dropped.

    See also _step_filter_observations().
    """

    filtered_obs_map = {}
    for obs_idx, cyber_obs_obj_map in six.iteritems(observations):
        filtered_cyber_obs_obj_map = {}
        for cyber_obs_obj_id, cyber_obs_objs in six.iteritems(cyber_obs_obj_map):
            stepped_cyber_obs_objs = []
            for cyber_obs_obj in cyber_obs_objs:
                if not isinstance(cyber_obs_obj, list):
                    continue

                stepped_cyber_obs_objs.extend(cyber_obs_obj)

            if len(stepped_cyber_obs_objs) > 0:
                filtered_cyber_obs_obj_map[cyber_obs_obj_id] = stepped_cyber_obs_objs

        if filtered_cyber_obs_obj_map:
            filtered_obs_map[obs_idx] = filtered_cyber_obs_obj_map

    return filtered_obs_map


def _get_first_terminal_descendant(ctx):
    """
    Gets the first terminal descendant of the given parse tree node.
    I use this with nodes for literals to get the actual literal terminal
    node, from which I can get the literal value itself.
    """
    if isinstance(ctx, antlr4.TerminalNode):
        return ctx

    # else, it's a RuleContext
    term = None
    for child in ctx.getChildren():
        term = _get_first_terminal_descendant(child)
        if term is not None:
            break

    return term


def _literal_terminal_to_python_val(literal_terminal):
    """
    Use the table of "coercer" functions to convert a terminal node from the
    parse tree to a Python value.
    """
    token_type = literal_terminal.getSymbol().type
    token_text = literal_terminal.getText()

    if token_type in _TOKEN_TYPE_COERCERS:
        coercer = _TOKEN_TYPE_COERCERS[token_type]
        try:
            python_value = coercer(token_text)
        except Exception as e:
            six.raise_from(MatcherException(u"Invalid {}: {}".format(
                STIXPatternParser.symbolicNames[token_type], token_text
            )), e)
    else:
        raise MatcherInternalError(u"Unsupported literal type: {}".format(
            STIXPatternParser.symbolicNames[token_type]))

    return python_value


def _like_to_regex(like):
    """Convert a "like" pattern to a regex."""

    with io.StringIO() as sbuf:
        # "like" always must match the whole string, so surround with anchors
        sbuf.write(u"^")
        for c in like:
            if c == u"%":
                sbuf.write(u".*")
            elif c == u"_":
                sbuf.write(u".")
            else:
                if not c.isalnum():
                    sbuf.write(u'\\')
                sbuf.write(c)
        sbuf.write(u"$")
        s = sbuf.getvalue()

    # print(like, "=>", s)
    return s


def _str_to_datetime(timestamp_str, ignore_case=False):
    """
    Convert a timestamp string from a pattern to a datetime.datetime object.
    If conversion fails, raises a ValueError.
    """

    # strptime() appears to work case-insensitively.  I think we require
    # case-sensitivity for timestamp literals inside patterns and JSON
    # (for the "T" and "Z" chars).  So check case first.
    if not ignore_case and any(c.islower() for c in timestamp_str):
        raise ValueError(u"Invalid timestamp format "
                         u"(require upper case): {}".format(timestamp_str))

    # Can't create a pattern with an optional part... so use two patterns
    if u"." in timestamp_str:
        fmt = u"%Y-%m-%dT%H:%M:%S.%fZ"
    else:
        fmt = u"%Y-%m-%dT%H:%M:%SZ"

    dt = datetime.datetime.strptime(timestamp_str, fmt)
    dt = dt.replace(tzinfo=dateutil.tz.tzutc())

    return dt


def _ip_addr_to_int(ip_str):
    """
    Converts a dotted-quad IP address string to an int.  The int is equal
    to binary representation of the four bytes in the address concatenated
    together, in the order they appear in the address.  E.g.

        1.2.3.4

    converts to

        00000001 00000010 00000011 00000100
      = 0x01020304
      = 16909060 (decimal)
    """
    try:
        ip_bytes = socket.inet_aton(ip_str)
    except socket.error:
        raise MatcherException(u"Invalid IPv4 address: {}".format(ip_str))

    int_val, = struct.unpack(">I", ip_bytes)  # unsigned big-endian

    return int_val


def _cidr_subnet_to_ints(subnet_cidr):
    """
    Converts a CIDR style subnet string to a 2-tuple of ints.  The
    first element is the IP address portion as an int, and the second
    is the prefix size.
    """

    slash_idx = subnet_cidr.find(u"/")
    if slash_idx == -1:
        raise MatcherException(u"Invalid CIDR subnet: {}".format(subnet_cidr))

    ip_str = subnet_cidr[:slash_idx]
    prefix_str = subnet_cidr[slash_idx+1:]

    ip_int = _ip_addr_to_int(ip_str)
    if not prefix_str.isdigit():
        raise MatcherException(u"Invalid CIDR subnet: {}".format(subnet_cidr))
    prefix_size = int(prefix_str)

    if prefix_size < 1 or prefix_size > 32:
        raise MatcherException(u"Invalid CIDR subnet: {}".format(subnet_cidr))

    return ip_int, prefix_size


def _ip_or_cidr_in_subnet(ip_or_cidr_str, subnet_cidr):
    """
    Determine if the IP or CIDR subnet given in the first arg, is contained
    within the CIDR subnet given in the second arg.

    :param ip_or_cidr_str: An IP address as a string in dotted-quad notation,
        or a subnet as a string in CIDR notation
    :param subnet_cidr: A subnet as a string in CIDR notation
    """

    # First arg is the containee, second is the container.  Does the
    # container contain the containee?

    # Handle either plain IP or CIDR notation for the containee.
    slash_idx = ip_or_cidr_str.find(u"/")
    if slash_idx == -1:
        containee_ip_int = _ip_addr_to_int(ip_or_cidr_str)
        containee_prefix_size = 32
    else:
        containee_ip_int, containee_prefix_size = _cidr_subnet_to_ints(
            ip_or_cidr_str)

    container_ip_int, container_prefix_size = _cidr_subnet_to_ints(subnet_cidr)

    if container_prefix_size > containee_prefix_size:
        return False

    # Use container mask for both IPs
    container_mask = ((1 << container_prefix_size) - 1) << \
                     (32 - container_prefix_size)
    masked_containee_ip = containee_ip_int & container_mask
    masked_container_ip = container_ip_int & container_mask

    return masked_containee_ip == masked_container_ip


def _obs_map_prop_test(obs_map, predicate):
    """
    Property tests always perform the same structural transformation of
    observation data on the stack.  There are several callbacks within the
    matcher listener to do various types of tests, and I found I was having to
    update the same basic code in many places.  So I have factored it out to
    this function.  As the pattern design evolves and my program changes, the
    data structures and required transformations evolve too.  This gives me a
    single place to update one of these transformations, instead of having to
    do it repeatedly in N different places.  It also gives a nice centralized
    place to document it.

    Required structure for obs_map is the result of object path selection;
    see MatchListener.exitObjectPath() for details.

    The structure of the result of a property test is:

    {
      obs_idx: {cyber_obs_obj_id1, cyber_obs_obj_id2, ...},
      obs_idx: {cyber_obs_obj_id1, cyber_obs_obj_id2, ...},
      etc...
    }

    I.e. for each observation, a set of Cyber Observable object IDs is associated, which
    are the "root" objects which caused the match.  The Cyber Observable object ID info
    is necessary to eliminate observation expression matches not rooted at the
    same Cyber Observable object.

    :param obs_map: Observation data, as selected by an object path.
    :param predicate: This encompasses the actual test to perform.  It must
        be a function of one parameter, which returns True or False.
    :return: The transformed and filtered data, according to predicate.
    """
    passed_obs = {}
    for obs_idx, cyber_obs_obj_map in six.iteritems(obs_map):
        passed_cyber_obs_obj_roots = set()
        for cyber_obs_obj_id, values in six.iteritems(cyber_obs_obj_map):
            for value in values:
                if predicate(value):
                    passed_cyber_obs_obj_roots.add(cyber_obs_obj_id)
                    break

        if passed_cyber_obs_obj_roots:
            passed_obs[obs_idx] = passed_cyber_obs_obj_roots

    return passed_obs
