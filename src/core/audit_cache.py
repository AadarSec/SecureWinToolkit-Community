import datetime


class AuditCache:
    """
    Global in-memory cache for Dashboard.

    Stores Windows Audit and Network Audit
    separately so Dashboard can combine them.
    """

    _results = {
        "windows": {},
        "network": {},
    }

    _last_updated = None

    # =====================================================
    # WINDOWS RESULTS
    # =====================================================

    @classmethod
    def set_windows_results(cls, results):

        cls._results["windows"] = results
        cls._last_updated = datetime.datetime.now()

    @classmethod
    def get_windows_results(cls):

        return cls._results["windows"]

    # =====================================================
    # NETWORK RESULTS
    # =====================================================

    @classmethod
    def set_network_results(cls, results):

        cls._results["network"] = results
        cls._last_updated = datetime.datetime.now()

    @classmethod
    def get_network_results(cls):

        return cls._results["network"]
        # =====================================================
    # ALL RESULTS
    # =====================================================

    @classmethod
    def get_all_results(cls):
        """
        Returns both Windows and Network audit
        results together.
        """

        return cls._results

    # =====================================================
    # LAST UPDATED
    # =====================================================

    @classmethod
    def get_last_updated(cls):

        return cls._last_updated

    # =====================================================
    # HAS RESULTS
    # =====================================================

    @classmethod
    def has_results(cls):

        return (
            bool(cls._results["windows"]) or
            bool(cls._results["network"])
        )

    # =====================================================
    # TOTAL RESULTS
    # =====================================================

    @classmethod
    def get_total_results(cls):

        total = {}

        total.update(cls._results["windows"])
        total.update(cls._results["network"])

        return total

    # =====================================================
    # CLEAR CACHE
    # =====================================================

    @classmethod
    def clear(cls):

        cls._results = {
            "windows": {},
            "network": {},
        }

        cls._last_updated = None