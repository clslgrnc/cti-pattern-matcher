from stix2patterns.grammars.STIXPatternParser import STIXPatternParser

from stix2matcher.comparison_helper import _literal_terminal_to_python_val
from stix2matcher.exception import MatcherException


def _disjoint(first_seq, *rest_seq):
    """
    Checks whether the values in first sequence are disjoint from the
    values in the sequences in rest_seq.

    All 'None' values in the sequences are ignored.

    :return: True if first_seq is disjoint from the rest, False otherwise.
    """

    if len(rest_seq) == 0:
        return True

    # is there a faster way to do this?
    fs = set(x for x in first_seq if x is not None)
    return all(
        fs.isdisjoint(x for x in seq if x is not None)
        for seq in rest_seq
    )


# Constants used as return values of the _overlap() function.
_OVERLAP_NONE = 0
_OVERLAP = 1
_OVERLAP_TOUCH_INNER = 2
_OVERLAP_TOUCH_OUTER = 3
_OVERLAP_TOUCH_POINT = 4


def _overlap(min1, max1, min2, max2):
    """
    Test for overlap between interval [min1, max1] and [min2, max2].  For the
    purposes of this function, both intervals are treated as closed.  The
    result is one of four mutually exclusive values:

    - _OVERLAP_NONE: no overlap
    - _OVERLAP: the intervals overlap, such that they are not just touching
        at endpoints
    - _OVERLAP_TOUCH_INNER: the intervals overlap at exactly one point, and
        that point is max1==min2 (the "inner" two parameters of this function),
        and at least one is of non-zero length
    - _OVERLAP_TOUCH_OUTER: the intervals overlap at exactly one point, and
        that point is min1==max2 (the "outer" two parameters of this function),
        and at least one is of non-zero length
    - _OVERLAP_TOUCH_POINT: the intervals overlap at exactly one point, and
        both are zero-length (i.e. all parameters are equal).  This is a kind
        of corner case, to disambiguate it from inner/outer touches.

    The "touch" results allow callers to distinguish between ordinary overlaps
    and "touching" overlaps, and if it was touching, how the intervals touched
    each other.  This essentially allows callers to behave as if one or both
    if the intervals were not closed.  It pushes a little bit of the burden
    onto callers, when they don't want to treat both intervals as closed.  But
    caller code is still pretty simple; I think it simplifies the code overall.

    So overall, this function doesn't behave symmetrically.  You must carefully
    consider the order of intervals passed to the function, and what result(s)
    you're looking for.

    min1 must be <= max1, and analogously for min2 and max2.  There are
    assertions to emphasize this assumption.  The parameters can be of any type
    which is comparable for <= and equality.

    :param min1: the lower bound of the first interval
    :param max1: the upper bound of the first interval
    :param min2: the lower bound of the second interval
    :param max2: the upper bound of the second interval
    :return: The overlap result
    """
    assert min1 <= max1
    assert min2 <= max2

    if min1 == max1 == min2 == max2:
        return _OVERLAP_TOUCH_POINT
    elif max1 == min2:
        return _OVERLAP_TOUCH_INNER
    elif max2 == min1:
        return _OVERLAP_TOUCH_OUTER
    elif min2 <= max1 and min1 <= max2:
        return _OVERLAP

    return _OVERLAP_NONE


def _timestamp_intervals_within(timestamp_intervals, duration):
    """
    Checks whether it's possible to choose a timestamp from each of the given
    intervals such that all are within the given duration.  Viewed another way,
    this function checks whether an interval of the given duration exists,
    which overlaps all intervals in timestamp_intervals (including just
    "touching" on either end).

    :param timestamp_intervals: A sequence of 2-tuples of timestamps
        (datetime.datetime), each being a first_observed and last_observed
        timestamp for an observation.
    :param duration: A duration (dateutil.relativedelta.relativedelta).
    :return: True if a set of timestamps exists which satisfies the duration
        constraint; False otherwise.
    """

    # We need to find an interval of length 'duration' which overlaps all
    # timestamp_intervals (if one exists).  It is the premise of this
    # implementation that if any such intervals exist, one of them must be an
    # interval which touches at the earliest last_observed time and extends to
    # the "right" (in the direction of increasing time).  Therefore if that
    # interval is not a solution, then there are no solutions, and the given
    # intervals don't satisfy the constraint.
    #
    # The intuition is that the interval with the earliest last_observed time
    # is the furthest left as far as overlaps are concerned.  We construct a
    # test interval of the required duration which minimally overlaps this
    # furthest left interval, and maximizes its reach to the right to overlap
    # as many others as possible.  If we were to move the test interval right,
    # we lose overlap with our furthest-left interval, so none of those test
    # intervals can be a solution.  If we were able to move it left to reach a
    # previously unoverlapped interval and obtain a solution, then we didn't
    # find the earliest last_observed time, which is a contradiction w.r.t. the
    # aforementioned construction of the test interval, so that's not possible
    # either.  So it is impossible to improve the overlap by moving the test
    # interval either left or right; overlaps are maximized at our chosen test
    # interval location.  Therefore our test interval must be a solution, if
    # one exists.

    earliest_last_observed = min(interval[1] for interval in timestamp_intervals)
    test_interval = (earliest_last_observed, earliest_last_observed + duration)

    result = True
    for interval in timestamp_intervals:
        if not _overlap(interval[0], interval[1], *test_interval):
            result = False
            break

    return result


def _filtered_combinations(value_generator, combo_size, pre_filter=None, post_filter=None):
    """
    Finds combinations of values of the given size, from the given sequence,
    filtered according to the given predicates.

    This function builds up the combinations incrementally.
    `pre_filter` is invoked between two individual elements, before
    combinations are built.  This ensure that for any two elements in a given
    combination `pre_filter` returns True.

    The post_filter predicate is invoked on partial (and final) combinations.
    It can be used to check more global properties.
    It is invoked with each combination value as a separate
    argument.  E.g. if (1,2,3) is a candidate combination (or partial
    combination), the predicate is invoked as pred(1, 2, 3).  So the predicate
    will probably need a "*args"-style argument for capturing variable
    numbers of positional arguments.

    Because of the way combinations are built up incrementally, the predicate
    may assume that args 1 through N-1 already satisfy the predicate (they've
    already been run through it), which may allow you to optimize the
    implementation.  Arg 0 (or Arg N) is the "new" arg being tested to see if
    it can be prepended (or appended) to the rest of the args.

    :param values: The sequence of values
    :param combo_size: The desired combination size (must be >= 1)
    :param pre_filter: The pre filter predicate.
        If None (the default), no filtering is done.
    :param post_filter: The post filter predicate.
        If None (the default), no filtering is done.
    :return: The combinations, as a generator of tuples.
    """

    if combo_size < 1:
        raise ValueError(u"combo_size must be >= 1")
    elif combo_size == 1:
        # Each value is its own combo
        yield from (
            (value,) for value in value_generator
            if post_filter is None or post_filter(value)
        )
        return

    # combo_size > 1
    # generate up to combo_size - 1 values
    generated_values = [x for _, x in zip(range(combo_size - 1), value_generator)]

    for next_value in value_generator:
        filtered_values = [
            candidate
            for candidate in generated_values
            if pre_filter is None or pre_filter(candidate, next_value)
        ]
        sub_combos = _filtered_combinations_from_list(
            filtered_values,
            combo_size - 1,
            pre_filter,
            post_filter,
        )

        yield from (
            sub_combo + (next_value,)
            for sub_combo in sub_combos
            if post_filter is None or post_filter(*sub_combo, next_value)
        )
        generated_values.append(next_value)


def _filtered_combinations_from_list(value_list, combo_size, pre_filter=None, post_filter=None):
    """
    _filtered_combinations that works on lists

    :param value_list: The sequence of values
    :param combo_size: The desired combination size (must be >= 1)
    :param filter_pred: The filter predicate.  If None (the default), no
        filtering is done.
    :return: The combinations, as a generator of tuples.
    """

    if combo_size < 1:
        raise ValueError(u"combo_size must be >= 1")
    elif combo_size == 1:
        # Each value is its own combo
        yield from (
            (value,) for value in value_list
            if post_filter is None or post_filter(value)
        )
        return

    for i in range(len(value_list) + 1 - combo_size):
        filtered_values = [
            candidate
            for candidate in value_list[i + 1:]
            if pre_filter is None or pre_filter(value_list[i], candidate)
        ]

        sub_combos = _filtered_combinations_from_list(
            filtered_values,
            combo_size - 1,
            pre_filter,
            post_filter,
        )

        yield from (
            (value_list[i],) + sub_combo
            for sub_combo in sub_combos
            if post_filter is None or post_filter(value_list[i], *sub_combo)
        )


def _compute_expected_binding_size(ctx):
    """
    Computes the expected size of bindings to the given subset of the pattern.
    This is used purely to improve understandability of the generated bindings.
    It essentially allows me to add "filler" to generated bindings so they have
    the expected size.
    :param ctx: A node of the pattern parse tree representing a subset of the
        pattern.
    :return: A binding size (a number)
    """
    if isinstance(ctx, STIXPatternParser.ComparisonExpressionContext):
        return 1
    elif isinstance(ctx, STIXPatternParser.ObservationExpressionRepeatedContext):
        # Guess I ought to correctly handle the repeat-qualified observation
        # expressions too huh?
        child_count = _compute_expected_binding_size(
            ctx.observationExpression())
        rep_count = _literal_terminal_to_python_val(
            ctx.repeatedQualifier().IntPosLiteral())

        if rep_count < 1:
            raise MatcherException(u"Invalid repetition count: {}".format(
                rep_count))

        return child_count * rep_count

    else:
        # Not all node types have getChildren(), but afaict they all have
        # getChildCount() and getChild().
        return sum(_compute_expected_binding_size(ctx.getChild(i))
                   for i in range(ctx.getChildCount()))
