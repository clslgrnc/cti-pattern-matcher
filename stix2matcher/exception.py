from antlr4.error.ErrorListener import ErrorListener


class MatcherException(Exception):
    """Base class for matcher exceptions."""
    pass


class MatcherInternalError(MatcherException):
    """For errors that probably represent bugs or incomplete matcher
    implementation."""
    pass


class UnsupportedOperatorError(MatcherInternalError):
    """This means I just haven't yet added support for a particular operator.
    (A genuinely invalid operator ought to be caught during parsing right??)
    I found I was throwing internal errors for this in several places, so I
    just gave the error its own class to make it easier.
    """
    def __init__(self, op_str):
        super(UnsupportedOperatorError, self).__init__(
            u"Unsupported operator: '{}'".format(op_str)
        )


class MatcherErrorListener(ErrorListener):
    """
    Simple error listener which just remembers the last error message received.
    """
    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        self.error_message = u"{}:{}: {}".format(line, column, msg)
