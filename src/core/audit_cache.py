import datetime


class AuditCache:
    """
    Simple in-memory cache that stores the most recent audit results
    so other pages (like the Dashboard) can read them without having
    to re-run the audit themselves.
    """

    _results = {}
    _last_updated = None

    @classmethod
    def set_results(cls, results):

        cls._results = results
        cls._last_updated = datetime.datetime.now()

    @classmethod
    def get_results(cls):

        return cls._results

    @classmethod
    def get_last_updated(cls):

        return cls._last_updated

    @classmethod
    def has_results(cls):

        return bool(cls._results)

    @classmethod
    def clear(cls):

        cls._results = {}
        cls._last_updated = None
