from __future__ import print_function

import datetime
import io
import itertools
import pprint
import re
import unicodedata

import dateutil.relativedelta
import dateutil.tz
import six
from stix2patterns.grammars.STIXPatternListener import STIXPatternListener

from stix2matcher.comparison_helper import (
    _COMPARE_EQ_FUNCS,
    _COMPARE_ORDER_FUNCS,
    _get_first_terminal_descendant,
    _get_table_symmetric,
    _ip_or_cidr_in_subnet,
    _like_to_regex,
    _literal_terminal_to_python_val,
    _obs_map_prop_test,
    _step_filter_observations,
    _step_filter_observations_index_star,
    _str_to_datetime,
)
from stix2matcher.exception import (
    MatcherException,
    MatcherInternalError,
    UnsupportedOperatorError,
)
from stix2matcher.observation_helper import (
    _compute_expected_binding_size,
    _disjoint,
    _filtered_combinations,
    _overlap,
    _OVERLAP,
    _OVERLAP_TOUCH_OUTER,
    _timestamp_intervals_within,
)


def _dereference_cyber_obs_objs(cyber_obs_objs, cyber_obs_obj_references, ref_prop_name):
    """
    Dereferences a sequence of Cyber Observable object references.  Returns a list of
    the referenced objects.  If a reference does not resolve, it is not
    treated as an error, it is ignored.

    :param cyber_obs_objs: The context for reference resolution.  This is a mapping
        from Cyber Observable object ID to Cyber Observable object, i.e. the "objects" property of
        an observed-data SDO.
    :param cyber_obs_obj_references: An iterable of Cyber Observable object references.  These
        must all be strings, otherwise an exception is raised.
    :param ref_prop_name: For better error messages, the reference property
        being processed.
    :return: A list of the referenced Cyber Observable objects.  This could be fewer than
        the number of references, if some references didn't resolve.
    """
    dereferenced_cyber_obs_objs = []
    for referenced_obj_id in cyber_obs_obj_references:
        if not isinstance(referenced_obj_id, six.text_type):
            raise MatcherException(
                u"{} value of reference property '{}' was not "
                u"a string!  Got {}".format(
                    # Say "A value" if the property is a reference list,
                    # otherwise "The value".
                    u"A" if ref_prop_name.endswith(u"_refs") else u"The",
                    ref_prop_name, referenced_obj_id
                ))

        if referenced_obj_id in cyber_obs_objs:
            dereferenced_cyber_obs_objs.append(cyber_obs_objs[referenced_obj_id])

    return dereferenced_cyber_obs_objs


def _unicode_escape(src):
    """
    Escapes unicode characters in src, using the \\uXXXX syntax.  The
    unicode_escape codec escapes newlines too, so it's unusable for me.
    I have to write my own.  This will affect all codepoints > 127.
    """
    with io.StringIO() as dst:
        for c in src:
            ordc = ord(c)
            dst.write(
                c if ordc < 128
                else u"\\u{:04x}".format(ordc)
            )
        return dst.getvalue()


class MatchListener(STIXPatternListener):
    """
    A parser listener which performs pattern matching.  It works like an
    RPN calculator, pushing and popping intermediate results to/from an
    internal stack as the parse tree is traversed.  I tried to document
    for each callback method, what it consumes from the stack, and kind of
    values it produces.

    Matching a pattern is equivalent to finding a set of "bindings": an
    observation "bound" to each observation expression such that the
    constraints embodied in the pattern are satisfied.  The final value
    on top of the stack after the pattern matching process is complete contains
    these bindings.  If any bindings were found, the pattern matched, otherwise
    it didn't match.  (Assuming there were no errors during the matching
    process, of course.)

    There are different ways of doing this; one obvious way is a depth-first
    search, where you try different bindings, and backtrack to earlier
    decision points as you hit dead-ends.  I had originally been aiming to
    perform a complete pattern matching operation in a single post-order
    traversal of the parse tree, which means no backtracking.  So this matcher
    is implemented in a different way.  It essentially tracks all possible
    bindings at once, pruning away those which don't work as it goes.  This
    will likely use more memory, and the bookkeeping is a bit more complex,
    but it only needs one pass through the tree.  And at the end, you get
    many bindings, rather than just the first one found, as might
    be the case with a backtracking algorithm.

    Actually, through the use of generators to represent sets of bindings an
    implicit form of backtracking limits the memory usage.

    I made the conscious decision to skip some bindings in one particular case,
    to improve scalability (see exitObservationExpressionOr()) without
    affecting correctness.
    """

    def __init__(self, observed_data_sdos, verbose=False):
        """
        Initialize this match listener.

        :param observed_data_sdos: A list of STIX observed-data SDOs.
        :param verbose: If True, dump detailed information about triggered
            callbacks and stack activity to stdout.  This can provide useful
            information about what the matcher is doing.
        """

        # This "unpacks" the SDOs, creating repeated observations.  This
        # doesn't make copies of observations; the same dict is repeated
        # several times in the list.  Same goes for the timestamps.
        self.__observations = []
        self.__time_intervals = []  # 2-tuples of first,last timestamps
        for sdo in observed_data_sdos:

            number_observed = sdo["number_observed"]
            if number_observed < 1:
                raise MatcherException("SDO with invalid number_observed "
                                       "(must be >= 1): {}".format(
                                        number_observed))

            self.__observations.extend(
                itertools.repeat(sdo, number_observed)
            )
            self.__time_intervals.extend(
                itertools.repeat((_str_to_datetime(sdo["first_observed"]),
                                  _str_to_datetime(sdo["last_observed"])),
                                 number_observed)
            )

        self.__verbose = verbose
        # Holds intermediate results
        self.__compute_stack = []

    def __push(self, val, label=None):
        """Utility for pushing a value onto the compute stack.
        In verbose mode, show what's being pushed.  'label' lets you prefix
        the message with something... e.g. I imagine using a parser rule name.
        """
        self.__compute_stack.append(val)

        if self.__verbose:
            if label:
                print(u"{}: ".format(_unicode_escape(label)), end=u"")

            # Python2's pformat() returns str (the binary type), therefore
            # it must escape unicode chars.  Python3's pformat() returns str
            # (the text type), and does not escape unicode chars.  The
            # unicode_escape codec escapes newlines, which ruins the pretty
            # formatting, so it's not usable at all.
            if six.PY2:
                str_val = pprint.pformat(val).decode("ascii")
            else:
                str_val = _unicode_escape(pprint.pformat(val))
            print(u"push", str_val)

    def __pop(self, label=None):
        """Utility for popping a value off the compute stack.
        In verbose mode, show what's being popped.  'label' lets you prefix
        the message with something... e.g. I imagine using a parser rule name.
        """
        val = self.__compute_stack.pop()

        if self.__verbose:
            if label:
                print(u"{}: ".format(_unicode_escape(label)), end=u"")

            # Python2's pformat() returns str (the binary type), therefore
            # it must escape unicode chars.  Python3's pformat() returns str
            # (the text type), and does not escape unicode chars.  The
            # unicode_escape codec escapes newlines, which ruins the pretty
            # formatting, so it's not usable at all.
            if six.PY2:
                str_val = pprint.pformat(val).decode("ascii")
            else:
                str_val = _unicode_escape(pprint.pformat(val))
            print(u"pop", str_val)

        return val

    def matched(self):
        """
        After a successful parse tree traveral, this will tell you whether the
        pattern matched its input.  You should only call this if the parse
        succeeded and traversal completed without errors.  All of the found
        bindings are returned.

        The returned bindings will be a generator of tuples of ints.  These ints
        correspond to observations, not SDOs.  There is a difference when any
        SDOs have number_observed > 1.  `None` can also occur in any tuple.
        This corresponds to a portion of the pattern to which no observation
        was bound (because a binding was not necessary).  To get the actual
        SDOs from a binding, see get_sdos_from_binding().  If the pattern
        didn't match, an empty generator is returned.

        :return: The found bindings, if any.
        """
        # At the end of the parse, the top stack element will be a generator of
        # all the found bindings (as tuples).  If there is at least one, the
        # pattern matched.  If the tree traversal failed, the top stack element
        # could be anything... so don't call this function in that situation!
        if self.__compute_stack:
            yield from self.__compute_stack[0]
        return

    def get_sdos_from_binding(self, binding):
        """
        Resolves a binding to a list of SDOs.

        :param binding: A binding, as returned from matched(); it should be an
            iterable of ints.
        :return: A list of SDOs.
        """
        sdos = []
        for obs_idx in sorted(val for val in binding if val is not None):
            if not sdos or sdos[-1] is not self.__observations[obs_idx]:
                sdos.append(self.__observations[obs_idx])

        return sdos

    def exitObservationExpressions(self, ctx):
        """
        Implements the FOLLOWEDBY operator.  If there are two child nodes:

        Consumes two generators of binding tuples from the top of the stack, which
          are the RHS and LHS operands.
        Produces a joined generator of binding tuples.  This essentially produces a
          filtered cartesian cross-product of the LHS and RHS tuples.  Results
          include those with no duplicate observation IDs, and such that it is
          possible to choose legal timestamps (i.e. within the interval defined
          by the observation's first_observed and last_observed timestamps) for
          all observations such that the timestamps on the RHS binding are >=
          than the timestamps on the LHS binding.
        """
        num_operands = len(ctx.observationExpressions())

        if num_operands not in (0, 2):
            # Just in case...
            msg = u"Unexpected number of observationExpressions children: {}"
            raise MatcherInternalError(msg.format(num_operands))

        if num_operands == 0:
            # If only the one observationExpressionOr child, we don't need to do
            # anything to the top of the stack.
            return

        # num_operands == 2
        debug_label = u"exitObservationExpressions"

        rhs_bindings = self.__pop(debug_label)
        lhs_bindings = self.__pop(debug_label)

        # we need to return the filtered cartesian product of rhs_bindings
        # and lhs_bindings but they are generators:
        # we need to store the generated elements
        def joined_bindings():
            _rhs_cache = []
            _lhs_cache = []
            _next_rhs_binding = next(rhs_bindings, None)
            _next_lhs_binding = next(lhs_bindings, None)
            if _next_rhs_binding is None or _next_lhs_binding is None:
                # cache and one generator are empty
                return
            while _next_rhs_binding is not None or _next_lhs_binding is not None:
                # while there are new bindings to explore
                if _next_rhs_binding is not None:
                    # if there is a new rhs binding yield valid combinations
                    yield from self.__followed_by_right_join(_lhs_cache, _next_rhs_binding)
                    # update cache
                    _rhs_cache.append(_next_rhs_binding)
                    _next_rhs_binding = next(rhs_bindings, None)

                if _next_lhs_binding is not None:
                    # if there is a new rhs binding yield valid combinations
                    yield from self.__followed_by_left_join(_next_lhs_binding, _rhs_cache)
                    # update cache
                    _lhs_cache.append(_next_lhs_binding)
                    _next_lhs_binding = next(lhs_bindings, None)

        self.__push(joined_bindings(), debug_label)

    def __followed_by_left_join(self, lhs_binding, rhs_bindings):
        # Yield all valid FOLLOWEDBY joins between a single lhs_binding
        # and a list of rhs_bindings

        # To ensure a satisfying selection of timestamps is possible,
        # we make the most optimistic choices: choose the earliest
        # possible timestamps for LHS bindings and latest possible for
        # RHS bindings.  Then as a shortcut, only ensure proper
        # ordering of the latest LHS timestamp and earliest RHS
        # timestamp.
        latest_lhs_first_timestamp = self.__latest_first_timestamp(lhs_binding)

        for rhs_binding in rhs_bindings:

            if _disjoint(lhs_binding, rhs_binding):
                earliest_rhs_last_timestamp = self.__earliest_last_timestamp(rhs_binding)

                if latest_lhs_first_timestamp <= earliest_rhs_last_timestamp:
                    yield (lhs_binding + rhs_binding)

    def __followed_by_right_join(self, lhs_bindings, rhs_binding):
        # Yield all valid FOLLOWEDBY joins between a list of lhs_bindings
        # and a single rhs_binding

        earliest_rhs_last_timestamp = self.__earliest_last_timestamp(rhs_binding)

        for lhs_binding in lhs_bindings:

            if _disjoint(lhs_binding, rhs_binding):
                latest_lhs_first_timestamp = self.__latest_first_timestamp(lhs_binding)

                if latest_lhs_first_timestamp <= earliest_rhs_last_timestamp:
                    yield (lhs_binding + rhs_binding)

    def __latest_first_timestamp(self, binding):
        return max(
            self.__time_intervals[obs_id][0]
            for obs_id in binding
            if obs_id is not None
        )

    def __earliest_last_timestamp(self, binding):
        return min(
            self.__time_intervals[obs_id][1]
            for obs_id in binding
            if obs_id is not None
        )

    def exitObservationExpressionOr(self, ctx):
        """
        Implements the pattern-level OR operator.  If there are two child
        nodes:

        Consumes two generators of binding tuples from the top of the stack, which
          are the RHS and LHS operands.
        Produces a joined generator of binding tuples.  This produces a sort of
          outer join: result tuples include the LHS values with all RHS
          values set to None, and vice versa.  Result bindings with values
          from both LHS and RHS are not included, to improve scalability
          (reduces the number of results, without affecting correctness).

        I believe the decision to include only one-sided bindings to be
        justified because binding additional observations here only serves to
        eliminate options for binding those observations to other parts of
        the pattern later.  So it can never enable additional binding
        possibilities, only eliminate them.

        In case you're wondering about repeat-qualified sub-expressions
        ("hey, if you reduce the number of bindings, you might not reach
        the required repeat count for a repeat-qualified sub-expression!"),
        note that none of these additional bindings would be disjoint w.r.t.
        the base set of one-sided bindings.  Therefore, they could never
        be combined with the base set to satisfy an increased repeat count.

        So basically, this base set maximizes binding opportunities elsewhere
        in the pattern, and does not introduce "false negatives".  It will
        result in some possible bindings not being found, but only when it
        would be extra noise anyway.  That improves scalability.
        """
        num_operands = len(ctx.observationExpressionOr())

        if num_operands not in (0, 2):
            # Just in case...
            msg = u"Unexpected number of observationExpressionOr children: {}"
            raise MatcherInternalError(msg.format(num_operands))

        if num_operands == 0:
            return

        # num_operands == 2:
        debug_label = u"exitObservationExpressionOr"

        rhs_bindings = self.__pop(debug_label)
        lhs_bindings = self.__pop(debug_label)

        # Compute tuples of None values, for each side (rhs/lhs), whose
        # lengths are equal to the bindings on those sides.  These will
        # be concatenated with actual bindings to produce the results.
        # These are kind of like None'd "placeholder" bindings, since we
        # want each joined binding to include actual bindings from only the
        # left or right side, not both.  We fill in None's for the side
        # we don't want to include.
        #
        # There are special cases when one side has no bindings.
        # We would like the resulting binding sizes to match up to the
        # number of observation expressions in the pattern, but if one
        # side's bindings are empty, we can't easily tell what size they
        # would have been.  So I traverse that part of the subtree to
        # obtain a size.  Algorithm correctness doesn't depend on this
        # "filler", but it helps users understand how the resulting
        # bindings match up with the pattern.
        first_lhs_binding = next(lhs_bindings, None)
        first_rhs_binding = next(rhs_bindings, None)
        if first_lhs_binding is not None:
            lhs_binding_none = (None,) * len(first_lhs_binding)
        else:
            left_binding_size = _compute_expected_binding_size(
                ctx.observationExpressionOr(0))
            lhs_binding_none = (None,) * left_binding_size
        if first_rhs_binding is not None:
            rhs_binding_none = (None,) * len(first_rhs_binding)
        else:
            right_binding_size = _compute_expected_binding_size(
                ctx.observationExpressionOr(0))
            rhs_binding_none = (None,) * right_binding_size

        def joined_bindings():
            _lhs_binding = first_lhs_binding
            _rhs_binding = first_rhs_binding
            while _lhs_binding is not None or _rhs_binding is not None:
                if _lhs_binding is not None:
                    yield _lhs_binding + rhs_binding_none
                    _lhs_binding = next(lhs_bindings, None)
                if _rhs_binding is not None:
                    yield lhs_binding_none + _rhs_binding
                    _rhs_binding = next(rhs_bindings, None)

        self.__push(joined_bindings(), debug_label)

    def exitObservationExpressionAnd(self, ctx):
        """
        Implements the pattern-level AND operator.  If there are two child
        nodes:

        Consumes two generators of binding tuples from the top of the stack, which
          are the RHS and LHS operands.
        Produces a joined generator of binding tuples.  All joined tuples are
          produced which include lhs and rhs values without having any
          duplicate observation IDs.
        """
        num_operands = len(ctx.observationExpressionAnd())

        if num_operands not in (0, 2):
            # Just in case...
            msg = u"Unexpected number of observationExpressionAnd children: {}"
            raise MatcherInternalError(msg.format(num_operands))

        if num_operands == 0:
            return

        # num_operands == 2:
        debug_label = u"exitObservationExpressionAnd"

        rhs_bindings = self.__pop(debug_label)
        lhs_bindings = self.__pop(debug_label)

        # we need to return the cartesian product of rhs_bindings and lhs_bindings
        # but they are generators: we need to store the generated elements
        def joined_bindings():
            _rhs_cache = []
            _lhs_cache = []
            _next_rhs_binding = next(rhs_bindings, None)
            _next_lhs_binding = next(lhs_bindings, None)
            if _next_rhs_binding is None or _next_lhs_binding is None:
                # cache and one generator are empty
                return
            while _next_rhs_binding is not None or _next_lhs_binding is not None:
                # while there are new bindings to explore
                if _next_rhs_binding is not None:
                    # if there is a new rhs binding
                    for lhs_binding in _lhs_cache:
                        # yield valid combinations
                        if _disjoint(lhs_binding, _next_rhs_binding):
                            yield (lhs_binding + _next_rhs_binding)
                    # update cache
                    _rhs_cache.append(_next_rhs_binding)
                    _next_rhs_binding = next(rhs_bindings, None)

                if _next_lhs_binding is not None:
                    # if there is a new rhs binding
                    for rhs_binding in _rhs_cache:
                        # yield valid combinations
                        if _disjoint(_next_lhs_binding, rhs_binding):
                            yield (_next_lhs_binding + rhs_binding)
                    # update cache
                    _lhs_cache.append(_next_lhs_binding)
                    _next_lhs_binding = next(lhs_bindings, None)

        self.__push(joined_bindings(), debug_label)

    def exitObservationExpressionSimple(self, ctx):
        """
        Consumes a the results of the inner comparison expression.  See
        exitComparisonExpression().
        Produces: a generator of 1-tuples of the IDs.  At this stage, the root
        Cyber Observable object IDs are no longer needed, and are dropped.

        This is a preparatory transformative step, so that higher-level
        processing has consistent structures to work with (always generator of
        tuples).
        """

        debug_label = u"exitObservationExpression (simple)"
        obs_ids = self.__pop(debug_label)
        obs_id_tuples = ((obs_id,) for obs_id in obs_ids.keys())
        self.__push(obs_id_tuples, debug_label)

    # Don't need to do anything for exitObservationExpressionCompound

    def exitObservationExpressionRepeated(self, ctx):
        """
        Consumes a genrator of bindings for the qualified observation expression.
        Produces a genrator of bindings which account for the repetition. The
        length of each new binding is equal to the length of the old bindings
        times the repeat count.
        """

        rep_count = _literal_terminal_to_python_val(
            ctx.repeatedQualifier().IntPosLiteral()
        )
        debug_label = u"exitObservationExpressionRepeated ({})".format(
            rep_count
        )

        bindings = self.__pop(debug_label)

        # Need to find all 'rep_count'-sized disjoint combinations of
        # bindings.
        if rep_count < 1:
            raise MatcherException(u"Invalid repetition count: {}".format(
                rep_count))
        elif rep_count == 1:
            # As an optimization, if rep_count is 1, we use the bindings
            # as-is.
            filtered_bindings = bindings
        else:
            # A generator of tuples goes in (bindings)
            filtered_bindings = _filtered_combinations(bindings, rep_count,
                                                       pre_filter=_disjoint)
            # ... and a generator of tuples of tuples comes out
            # (filtered_bindings).  The following flattens each outer
            # tuple.  I could have also written a generic flattener, but
            # since this structure is predictable, I could do something
            # simpler.  Other code dealing with bindings doesn't expect any
            # nested structure, so I do the flattening here.
            filtered_bindings = (tuple(itertools.chain.from_iterable(binding))
                                 for binding in filtered_bindings)

        self.__push(filtered_bindings, debug_label)

    def exitObservationExpressionWithin(self, ctx):
        """
        Consumes (1) a duration, as a dateutil.relativedelta.relativedelta
          object (see exitWithinQualifier()), and (2) a generator of bindings.
        Produces a generator of bindings which are temporally filtered according
          to the given duration.
        """

        debug_label = u"exitObservationExpressionWithin"

        duration = self.__pop(debug_label)
        bindings = self.__pop(debug_label)

        def check_within(binding):
            return _timestamp_intervals_within(
                [
                    self.__time_intervals[obs_id]
                    for obs_id in binding
                    if obs_id is not None
                ],
                duration
            )

        filtered_bindings = filter(check_within, bindings)

        self.__push(filtered_bindings, debug_label)

    def exitObservationExpressionStartStop(self, ctx):
        """
        Consumes (1) a time interval as a pair of datetime.datetime objects,
          and (2) a generator of bindings.
        Produces a generator of bindings which are temporally filtered according
          to the given time interval.  A binding passes the test if it is
          possible to select legal timestamps for all observations which are
          within the start/stop interval, not including the stop value, which
          is disallowed by the spec.  Viewed another way, we require overlap
          with the SDO interval and start/stop interval, including only touching
          at the start point, but not including only touching at the stop
          point.
        """

        debug_label = u"exitObservationExpressionStartStop"

        # In this case, these are start and stop timestamps as
        # datetime.datetime objects (see exitStartStopQualifier()).
        start_time, stop_time = self.__pop(debug_label)
        bindings = self.__pop(debug_label)

        def check_within(binding):
            return all(
                    _overlap(start_time, stop_time, *self.__time_intervals[obs_id])
                    in (_OVERLAP, _OVERLAP_TOUCH_OUTER)
                    for obs_id in binding if obs_id is not None
                )

        filtered_bindings = filter(check_within, bindings)

        # If start and stop are equal, the constraint is impossible to
        # satisfy, since a value can't be both >= and < the same number.
        # And of course it's impossible if start > stop.
        if start_time < stop_time:
            filtered_bindings = filter(check_within, bindings)
        else:
            filtered_bindings = iter(())

        self.__push(iter(filtered_bindings), debug_label)

    def exitStartStopQualifier(self, ctx):
        """
        Consumes nothing
        Produces a (datetime, datetime) 2-tuple containing the start and stop
          times.
        """

        start_str = _literal_terminal_to_python_val(ctx.StringLiteral(0))
        stop_str = _literal_terminal_to_python_val(ctx.StringLiteral(1))

        # If the language used timestamp literals here, this could go away...
        try:
            start_dt = _str_to_datetime(start_str)
            stop_dt = _str_to_datetime(stop_str)
        except ValueError as e:
            # re-raise as MatcherException.
            raise six.raise_from(MatcherException(*e.args), e)

        self.__push((start_dt, stop_dt), u"exitStartStopQualifier")

    def exitWithinQualifier(self, ctx):
        """
        Consumes nothing (the unit is always seconds).
        Produces a dateutil.relativedelta.relativedelta object, representing
          the specified interval.
        """

        value = _literal_terminal_to_python_val(ctx.FloatPosLiteral() or ctx.IntPosLiteral())
        debug_label = u"exitWithinQualifier ({})".format(value)
        if value <= 0:
            raise MatcherException(u"Invalid WITHIN value (must be positive): {}".format(value))

        delta = dateutil.relativedelta.relativedelta(seconds=value)

        self.__push(delta, debug_label)

    def exitComparisonExpression(self, ctx):
        """
        Consumes zero or two maps of observation IDs produced by child
          propTest's (see _obs_map_prop_test()) and/or
          sub-comparison-expressions.
        Produces: if one child expression, this callback does nothing.  If
          two, the top two maps on the stack are combined into a single map of
          observation IDs.

          This implements the "OR" operator.  So the maps are merged (union);
          observation IDs which are shared between both operands have their
          Cyber Observable object ID sets unioned in the result.
        """

        debug_label = u"exitComparisonExpression"
        num_or_operands = len(ctx.comparisonExpression())

        # Just in case...
        if num_or_operands not in (0, 2):
            msg = u"Unexpected number of comparisonExpression children: {}"
            raise MatcherInternalError(msg.format(num_or_operands))

        if num_or_operands == 2:
            # The result is collected into obs1.
            obs2 = self.__pop(debug_label)
            obs1 = self.__pop(debug_label)

            # We union the observation IDs and their corresponding
            # Cyber Observable object ID sets.
            for obs_id, cyber_obs_obj_ids in six.iteritems(obs2):
                if obs_id in obs1:
                    obs1[obs_id] |= cyber_obs_obj_ids
                else:
                    obs1[obs_id] = cyber_obs_obj_ids

            self.__push(obs1, debug_label)

    def exitComparisonExpressionAnd(self, ctx):
        """
        Consumes zero or two maps of observation IDs produced by child
          propTest's (see _obs_map_prop_test()) and/or
          sub-comparison-expressions.
        Produces: if one child expression, this callback does nothing.  If
          two, the top two maps on the stack are combined into a single map of
          observation IDs.

          This implements the "AND" operator.  So the result map has those IDs
          common to both (intersection); their Cyber Observable object ID sets are also
          intersected.  If this latter intersection is empty, the corresponding
          observation is dropped.
        """

        debug_label = u"exitComparisonExpressionAnd"
        num_and_operands = len(ctx.comparisonExpressionAnd())

        # Just in case...
        if num_and_operands not in (0, 2):
            msg = u"Unexpected number of comparisonExpression children: {}"
            raise MatcherInternalError(msg.format(num_and_operands))

        if num_and_operands == 2:
            # The result is collected into obs1.
            obs2 = self.__pop(debug_label)
            obs1 = self.__pop(debug_label)

            # We intersect the observation IDs and their corresponding
            # Cyber Observable object ID sets.  If any of the Cyber Observable object ID set
            # intersections is empty, we drop the observation from the
            # result.
            obs_ids_to_drop = []
            for obs_id, cyber_obs_obj_ids in six.iteritems(obs1):
                if obs_id in obs2:
                    obs1[obs_id] &= obs2[obs_id]
                    if not obs1[obs_id]:
                        obs_ids_to_drop.append(obs_id)
                else:
                    obs_ids_to_drop.append(obs_id)

            # Now drop the ones we found (can't modify as we iterated
            # above, so this needs to be a separate pass).
            for obs_id in obs_ids_to_drop:
                del obs1[obs_id]

            self.__push(obs1, debug_label)

    def exitPropTestEqual(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        It's okay if the operands are of different type and comparison is
        not supported: they will compare unequal.  (Note: this would include
        things like pairs of dicts and lists which have the same contents...
        should verify what to do here.)
        """

        # Figure out what literal value was given in the pattern
        literal_node = ctx.primitiveLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        op_tok = ctx.EQ() or ctx.NEQ()
        debug_label = u"exitPropTestEqual ({}{} {})".format(
            u"NOT " if ctx.NOT() else u"",
            op_tok.getText(),
            literal_terminal.getText()
        )

        obs_values = self.__pop(debug_label)

        def equality_pred(value):

            # timestamp hackage: if we have a timestamp literal from the
            # pattern and a string from the json, try to interpret the json
            # value as a timestamp too.
            if isinstance(literal_value, datetime.datetime) and \
                    isinstance(value, six.text_type):
                try:
                    value = _str_to_datetime(value)
                except ValueError as e:
                    six.raise_from(
                        MatcherException(u"Invalid timestamp in JSON: {}".format(
                            value
                        )), e)

            result = False
            eq_func = _get_table_symmetric(_COMPARE_EQ_FUNCS,
                                           type(literal_value),
                                           type(value))
            if eq_func is not None:
                result = eq_func(value, literal_value)

            if ctx.NEQ():
                result = not result

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, equality_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestOrder(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        If operand types are not supported for order-comparison, current
        spec says the result must be False.  But this means that for two
        values for which comparison is not supported, both a < b and
        a >= b would be false.  That's certainly not normal semantics for
        these operators...
        """
        # Figure out what literal value was given in the pattern
        literal_node = ctx.orderableLiteral()
        literal_terminal = _get_first_terminal_descendant(literal_node)
        literal_value = _literal_terminal_to_python_val(literal_terminal)
        op_tok = ctx.GT() or ctx.LT() or ctx.GE() or ctx.LE()
        debug_label = u"exitPropTestOrder ({}{} {})".format(
            u"NOT " if ctx.NOT() else u"",
            op_tok.getText(),
            literal_terminal.getText()
        )

        obs_values = self.__pop(debug_label)

        def order_pred(value):

            # timestamp hackage: if we have a timestamp literal from the
            # pattern and a string from the json, try to interpret the json
            # value as a timestamp too.
            if isinstance(literal_value, datetime.datetime) and \
                    isinstance(value, six.text_type):
                try:
                    value = _str_to_datetime(value)
                except ValueError as e:
                    six.raise_from(
                        MatcherException(u"Invalid timestamp in JSON: {}".format(
                            value
                        )), e)

            cmp_func = _get_table_symmetric(_COMPARE_ORDER_FUNCS,
                                            type(literal_value),
                                            type(value))

            if cmp_func is None:
                return False

            try:
                result = cmp_func(value, literal_value)
            except ValueError:
                # The only comparison func that raises ValueError as of this
                # writing is for binary<->string comparisons, when the string is
                # of the wrong form.  Spec says the result must be false.
                result = False
            else:
                if ctx.LT():
                    result = result < 0
                elif ctx.GT():
                    result = result > 0
                elif ctx.LE():
                    result = result <= 0
                elif ctx.GE():
                    result = result >= 0
                else:
                    # shouldn't ever happen, right?
                    raise UnsupportedOperatorError(op_tok.getText())

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, order_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestSet(self, ctx):
        """
        Consumes (1) a set object from exitSetLiteral(), and (2) an observation
           data map, {obs_id: {...}, ...}, representing selected values from
           Cyber Observable objects in each observation (grouped by observation index and
           root Cyber Observable object ID).  See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().
        """

        debug_label = u"exitPropTestSet{}".format(
            u" (not)" if ctx.NOT() else u""
        )
        s = self.__pop(debug_label)  # pop the set
        obs_values = self.__pop(debug_label)  # pop the observation values

        # Only need to check one member; exitSetLiteral() ensures that all
        # members of the set have the same type.
        is_set_of_timestamps = s and \
            isinstance(next(iter(s)), datetime.datetime)

        def set_pred(value):
            # timestamp hackage: if we have a set of timestamp literals from
            # the pattern and a string from the json, try to interpret the json
            # value as a timestamp too.
            if is_set_of_timestamps and isinstance(value, six.text_type):
                try:
                    value = _str_to_datetime(value)
                except ValueError as e:
                    six.raise_from(
                        MatcherException(u"Invalid timestamp in JSON: {}".format(
                            value
                        )), e)

            result = False
            try:
                result = value in s
            except TypeError:
                # Ignore errors about un-hashability.  Not all values
                # selected from a Cyber Observable object are hashable (e.g.
                # lists and dicts).  Those obviously can't be in the
                # given set!
                pass

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, set_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestLike(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """

        operand_str = _literal_terminal_to_python_val(ctx.StringLiteral())
        debug_label = u"exitPropTestLike ({}{})".format(
            u"not " if ctx.NOT() else u"",
            operand_str
        )

        obs_values = self.__pop(debug_label)

        operand_str = unicodedata.normalize("NFC", operand_str)
        regex = _like_to_regex(operand_str)
        # compile and cache this to improve performance
        compiled_re = re.compile(regex)

        def like_pred(value):
            # non-strings can't match
            if isinstance(value, six.text_type):
                value = unicodedata.normalize("NFC", value)
                result = compiled_re.match(value)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, like_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestRegex(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """

        regex_terminal = ctx.StringLiteral()
        debug_label = u"exitPropTestRegex ({}{})".format(
            u"not " if ctx.NOT() else u"",
            regex_terminal.getText()
        )

        obs_values = self.__pop(debug_label)

        regex = _literal_terminal_to_python_val(regex_terminal)
        regex = unicodedata.normalize("NFC", regex)
        compiled_re = re.compile(regex)

        # Support for binary pattern matching.
        is_binary_convertible = all(ord(c) < 256 for c in regex)
        if is_binary_convertible:
            if six.PY2:
                # This will be a pattern compiled from a unicode string, but
                # python2 doesn't seem to care.  It'll match against a 'str'
                # just fine.
                compiled_bin_re = compiled_re
            else:
                # Python3 requires an actual binary regex.
                bin_regex = six.binary_type(ord(c) for c in regex)
                compiled_bin_re = re.compile(bin_regex)

        def regex_pred(value):
            if isinstance(value, six.text_type):
                value = unicodedata.normalize("NFC", value)
                result = compiled_re.search(value)

            elif isinstance(value, six.binary_type):
                if is_binary_convertible:
                    result = compiled_bin_re.search(value)
                else:
                    result = False

            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, regex_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestIsSubset(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """
        subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitPropTestIsSubset ({}{})".format(
            u"not " if ctx.NOT() else u"",
            subnet_str
        )
        obs_values = self.__pop(debug_label)

        def subnet_pred(value):
            if isinstance(value, six.text_type):
                result = _ip_or_cidr_in_subnet(value, subnet_str)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, subnet_pred)

        self.__push(passed_obs, debug_label)

    def exitPropTestIsSuperset(self, ctx):
        """
        Consumes an observation data map, {obs_id: {...}, ...}, representing
          selected values from Cyber Observable objects in each observation
          (grouped by observation index and root Cyber Observable object ID).
          See exitObjectPath().
        Produces a map representing those observations with
          Cyber Observable object values which pass the test, each with an associated
          set of root Cyber Observable object IDs.  See _obs_map_prop_test().

        Non-string values are treated as non-matching, and don't produce
        errors.
        """
        ip_or_subnet_str = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitPropTestIsSuperset ({}{})".format(
            u"not " if ctx.NOT() else u"",
            ip_or_subnet_str
        )
        obs_values = self.__pop(debug_label)

        def contains_pred(value):
            if isinstance(value, six.text_type):
                result = _ip_or_cidr_in_subnet(ip_or_subnet_str, value)
            else:
                result = False

            if ctx.NOT():
                result = not result

            return result

        passed_obs = _obs_map_prop_test(obs_values, contains_pred)

        self.__push(passed_obs, debug_label)

    def exitObjectPath(self, ctx):
        """
        Consumes nothing from the stack
        Produces a mapping:
            {
              observation-idx: {
                  "cyber_obs_obj_id1": [value, value, ...],
                  "cyber_obs_obj_id2": [value, value, ...],
              },
              etc...
            }
          which are the values selected by the path, organized according to
          the the observations they belong to, and the "root" Cyber Observable objects
          which began a chain of dereferences (if any).  These will be used in
          subsequent comparisons to select some of the observations.
          I use observations' indices into the self.__observations list as
          identifiers.

        So this (and descendant rules) is where (the main) stack values come
        into being.
        """

        # We don't actually need to do any post-processing to the top stack
        # value.  But I keep this function here for the sake of documentation.
        pass

    def exitObjectType(self, ctx):
        """
        Consumes nothing from the stack.
        Produces a map, {observation-idx: {...}, ...}, representing those
        Cyber Observable objects with the given type.  See exitObjectPath().
        """
        type_token = ctx.IdentifierWithoutHyphen() or ctx.IdentifierWithHyphen()
        type_ = type_token.getText()

        results = {}
        for obs_idx, obs in enumerate(self.__observations):

            if "objects" not in obs:
                continue

            objects_from_this_obs = {}
            for obj_id, obj in six.iteritems(obs["objects"]):
                if u"type" in obj and obj[u"type"] == type_:
                    objects_from_this_obs[obj_id] = [obj]

            if len(objects_from_this_obs) > 0:
                results[obs_idx] = objects_from_this_obs

        self.__push(results, u"exitObjectType ({})".format(type_))

    def __dereference_objects(self, prop_name, obs_map):
        """
        If prop_name is a reference property, this "dereferences" it,
        substituting the referenced Cyber Observable object for the reference.  Reference
        properties end in "_ref" or "_refs".  The former must have a string
        value, the latter must be a list of strings.  Any references which
        don't resolve are dropped and don't produce an error.  The references
        are resolved only against the Cyber Observable objects in the same observation as
        the reference.

        If the property isn't a reference, this method does nothing.

        :param prop_name: The property which was just stepped, i.e. the "key"
            in a key path step.
        :param obs_map: The observation data after stepping, but before it
            has been pushed onto the stack.  This method acts as an additional
            "processing" step on that data.
        :return: If prop_name is not a reference property, obs_map is
            returned unchanged.  If it is a reference property, the
            dereferenced observation data is returned.
        """

        if prop_name.endswith(u"_ref"):
            # An object reference.  All top-level values should be
            # string Cyber Observable object IDs.
            dereferenced_obs_map = {}
            for obs_idx, cyber_obs_obj_map in six.iteritems(obs_map):
                dereferenced_cyber_obs_obj_map = {}
                for cyber_obs_obj_id, references in six.iteritems(cyber_obs_obj_map):
                    dereferenced_cyber_obs_objs = _dereference_cyber_obs_objs(
                        self.__observations[obs_idx]["objects"],
                        references,
                        prop_name
                    )

                    if len(dereferenced_cyber_obs_objs) > 0:
                        dereferenced_cyber_obs_obj_map[cyber_obs_obj_id] = \
                            dereferenced_cyber_obs_objs

                if len(dereferenced_cyber_obs_obj_map) > 0:
                    dereferenced_obs_map[obs_idx] = dereferenced_cyber_obs_obj_map

            obs_map = dereferenced_obs_map

        elif prop_name.endswith(u"_refs"):
            # A list of object references.  All top-level values should
            # be lists (of Cyber Observable object references).
            dereferenced_obs_map = {}
            for obs_idx, cyber_obs_obj_map in six.iteritems(obs_map):
                dereferenced_cyber_obs_obj_map = {}
                for cyber_obs_obj_id, reference_lists in six.iteritems(cyber_obs_obj_map):
                    dereferenced_cyber_obs_obj_lists = []
                    for reference_list in reference_lists:
                        if not isinstance(reference_list, list):
                            raise MatcherException(
                                u"The value of reference list property '{}' was not "
                                u"a list!  Got {}".format(
                                    prop_name, reference_list
                                ))

                        dereferenced_cyber_obs_objs = _dereference_cyber_obs_objs(
                            self.__observations[obs_idx]["objects"],
                            reference_list,
                            prop_name
                        )

                        if len(dereferenced_cyber_obs_objs) > 0:
                            dereferenced_cyber_obs_obj_lists.append(
                                dereferenced_cyber_obs_objs)

                    if len(dereferenced_cyber_obs_obj_lists) > 0:
                        dereferenced_cyber_obs_obj_map[cyber_obs_obj_id] = \
                            dereferenced_cyber_obs_obj_lists

                if len(dereferenced_cyber_obs_obj_map) > 0:
                    dereferenced_obs_map[obs_idx] = dereferenced_cyber_obs_obj_map

            obs_map = dereferenced_obs_map

        return obs_map

    def exitFirstPathComponent(self, ctx):
        """
        Consumes the results of exitObjectType.
        Produces a similar structure, but with Cyber Observable objects which
          don't have the given property, filtered out.  For those which
          do have the property, the property value is substituted for
          the object.  If the property was a reference, a second substitution
          occurs: the referent is substituted in place of the reference (if
          the reference resolves).  This enables subsequent path steps to step
          into the referenced Cyber Observable object(s).

          If all Cyber Observable objects from an observation are filtered out, the
          observation is dropped.
        """

        if ctx.IdentifierWithoutHyphen():
            prop_name = ctx.IdentifierWithoutHyphen().getText()
        else:
            prop_name = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitFirstPathComponent ({})".format(prop_name)
        obs_val = self.__pop(debug_label)

        filtered_obs_map = _step_filter_observations(obs_val, prop_name)
        dereferenced_obs_map = self.__dereference_objects(prop_name,
                                                          filtered_obs_map)

        self.__push(dereferenced_obs_map, debug_label)

    def exitKeyPathStep(self, ctx):
        """
        Does the same as exitFirstPathComponent().
        """
        if ctx.IdentifierWithoutHyphen():
            prop_name = ctx.IdentifierWithoutHyphen().getText()
        else:
            prop_name = _literal_terminal_to_python_val(ctx.StringLiteral())

        debug_label = u"exitKeyPathStep ({})".format(prop_name)
        obs_val = self.__pop(debug_label)

        filtered_obs_map = _step_filter_observations(obs_val, prop_name)
        dereferenced_obs_map = self.__dereference_objects(prop_name,
                                                          filtered_obs_map)

        self.__push(dereferenced_obs_map, debug_label)

    def exitIndexPathStep(self, ctx):
        """
        Does the same as exitFirstPathComponent(), but takes a list index
        step.
        """
        if ctx.IntPosLiteral() or ctx.IntNegLiteral():
            index = _literal_terminal_to_python_val(
                ctx.IntPosLiteral() or ctx.IntNegLiteral()
            )
            debug_label = u"exitIndexPathStep ({})".format(index)
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations(obs_val, index)

        elif ctx.ASTERISK():
            # In this case, we step into all of the list elements.
            debug_label = u"exitIndexPathStep (*)"
            obs_val = self.__pop(debug_label)

            filtered_obs_map = _step_filter_observations_index_star(obs_val)

        else:
            # reallly shouldn't happen...
            raise MatcherInternalError(u"Unsupported index path step!")

        self.__push(filtered_obs_map, debug_label)

    def exitSetLiteral(self, ctx):
        """
        Consumes nothing
        Produces a python set object with values from the set literal
        """

        literal_nodes = ctx.primitiveLiteral()

        # Make a python set from the set literal.  Can't go directly to a set
        # though because values of heterogenous types might overwrite each
        # other, e.g. 1 and True (which both hash to 1).  So collect the values
        # to an intermediate list first.
        first_type = None
        has_only_numbers = is_homogenous = True
        python_values = []
        for literal_node in literal_nodes:
            literal_terminal = _get_first_terminal_descendant(literal_node)
            literal_value = _literal_terminal_to_python_val(literal_terminal)

            if first_type is None:
                first_type = type(literal_value)
            elif first_type is not type(literal_value):
                is_homogenous = False

            # bool is a subclass of int!
            if not isinstance(literal_value, (int, float)) or \
                    isinstance(literal_value, bool):
                has_only_numbers = False

            python_values.append(literal_value)

        if python_values:
            if is_homogenous:
                s = set(python_values)
            elif has_only_numbers:
                # If it's mix of just ints and floats, let that pass through.
                # Python treats those more interoperably, e.g. 1.0 == 1, and
                # hash(1.0) == hash(1), so I don't think it's necessary to
                # promote ints to floats.
                s = set(python_values)
                is_homogenous = True

            if not is_homogenous:
                raise MatcherException(u"Nonhomogenous set: {}".format(
                    ctx.getText()))
        else:
            s = set()

        self.__push(s, u"exitSetLiteral ({})".format(ctx.getText()))
