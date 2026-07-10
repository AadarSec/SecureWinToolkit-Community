"""
SecureWin Toolkit

Security Score Engine

Responsible for:

• Windows Audit Score
• Network Audit Score
• Overall Security Score
• Security Posture
"""

from __future__ import annotations

from typing import Dict, List

from src.core.scanner_metadata import (

    MODULE,

    SCANNER_METADATA,

    get_scanner_metadata,

    is_score_enabled

)

from src.core.security_weights import (

    get_module_weight,

    get_category_weight,

    get_status_penalty,

    get_severity_multiplier,

    get_security_posture,

    clamp_score

)


# ==========================================================
# STATUS CONSTANTS
# ==========================================================

STATUS = {

    "PASSED": "Passed",

    "WARNING": "Warning",

    "CRITICAL": "Critical",

    "INFORMATION": "Information",

    "NOT_SCANNED": "Not Scanned"

}


# ==========================================================
# SECURITY SCORE ENGINE
# ==========================================================

class SecurityScoreEngine:


    def __init__(self):

        self.results: Dict[str, dict] = {}


    # ------------------------------------------------------
    # Result Management
    # ------------------------------------------------------

    def update_results(
        self,
        results: dict
    ) -> None:
        """
        Replace current scan results.
        """

        self.results = results.copy()


    def clear(self) -> None:
        """
        Clears current scan results.
        """

        self.results.clear()


    def refresh(
        self,
        results: dict
    ) -> dict:
        """
        Refresh engine using latest
        scan results.
        """

        self.update_results(results)

        return self.calculate_summary()


    # ------------------------------------------------------
    # Scanner Helpers
    # ------------------------------------------------------

    def scanner_exists(
        self,
        scanner_name: str
    ) -> bool:

        return scanner_name in self.results


    def get_scanner_result(
        self,
        scanner_name: str
    ) -> dict:

        return self.results.get(
            scanner_name,
            {}
        )


    def get_metadata(
        self,
        scanner_name: str
    ) -> dict:

        return get_scanner_metadata(
            scanner_name
        )


    def get_status(
        self,
        scanner_name: str
    ) -> str:
        """
        Returns scanner status.
        """

        result = self.get_scanner_result(
            scanner_name
        )

        if not result:

            return STATUS["NOT_SCANNED"]

        return result.get(

            "status",

            STATUS["NOT_SCANNED"]

        )


    def is_scanned(
        self,
        scanner_name: str
    ) -> bool:

        return (

            self.get_status(scanner_name)

            != STATUS["NOT_SCANNED"]

        )
            # ------------------------------------------------------
    # Score Calculation Helpers
    # ------------------------------------------------------

    def calculate_scanner_penalty(
        self,
        scanner_name: str
    ) -> float:
        """
        Calculate penalty contributed by a scanner.
        """

        if not is_score_enabled(scanner_name):
            return 0.0

        metadata = self.get_metadata(scanner_name)

        if not metadata:
            return 0.0

        status = self.get_status(scanner_name)

        if status == STATUS["NOT_SCANNED"]:
            return 0.0

        weight = metadata.get("weight", 0)

        severity = metadata.get("severity", 0)

        penalty = get_status_penalty(status)

        multiplier = get_severity_multiplier(
            severity
        )

        return (

            penalty

            * multiplier

            * weight

        )


    def calculate_scanner_score(
        self,
        scanner_name: str
    ) -> float:
        """
        Returns scanner score between
        0 and 100.
        """

        if not is_score_enabled(scanner_name):
            return 100.0

        metadata = self.get_metadata(scanner_name)

        if not metadata:
            return 100.0

        if self.get_status(scanner_name) == STATUS["NOT_SCANNED"]:
            return 100.0

        weight = metadata.get("weight", 0)

        if weight <= 0:
            return 100.0

        max_penalty = (

            100

            * weight

        )

        penalty = self.calculate_scanner_penalty(
            scanner_name
        )

        score = (

            100

            -

            (

                penalty

                / max_penalty

            )

            * 100

        )

        return clamp_score(score)


    # ------------------------------------------------------
    # Scanner Statistics
    # ------------------------------------------------------

    def get_scanner_statistics(
        self,
        scanner_name: str
    ) -> dict:
        """
        Returns complete scanner statistics.
        """

        metadata = self.get_metadata(scanner_name)

        return {

            "scanner": scanner_name,

            "status": self.get_status(scanner_name),

            "score": self.calculate_scanner_score(
                scanner_name
            ),

            "weight": metadata.get(
                "weight",
                0
            ),

            "severity": metadata.get(
                "severity",
                0
            ),

            "category": metadata.get(
                "category",
                ""
            ),

            "module": metadata.get(
                "module",
                ""
            ),

            "type": metadata.get(
                "type",
                ""
            )

        }
            # ------------------------------------------------------
    # Category Score Calculation
    # ------------------------------------------------------

    def get_category_scanners(
        self,
        category: str
    ) -> List[str]:
        """
        Returns all score-enabled scanners
        belonging to a category.
        """

        return [

            scanner

            for scanner, metadata

            in SCANNER_METADATA.items()

            if (

                metadata["category"] == category

                and

                metadata["enabled_for_score"]

            )

        ]


    def calculate_category_score(
        self,
        category: str
    ) -> float:
        """
        Calculate score for a category.
        """

        scanners = self.get_category_scanners(
            category
        )

        if not scanners:
            return 100.0

        scores = [

            self.calculate_scanner_score(scanner)

            for scanner in scanners

        ]

        return round(

            sum(scores) / len(scores),

            2

        )


    # ------------------------------------------------------
    # Module Score Calculation
    # ------------------------------------------------------

    def get_module_categories(
        self,
        module: str
    ) -> List[str]:
        """
        Returns unique score-enabled
        categories for a module.
        """

        categories = []

        for metadata in SCANNER_METADATA.values():

            if (

                metadata["module"] != module

                or

                not metadata["enabled_for_score"]

            ):

                continue

            category = metadata["category"]

            if category not in categories:

                categories.append(category)

        return categories


    def calculate_module_score(
        self,
        module: str
    ) -> float:
        """
        Calculate weighted score
        for a module.
        """

        categories = self.get_module_categories(
            module
        )

        if not categories:
            return 100.0

        weighted_score = 0.0

        total_weight = 0

        for category in categories:

            category_weight = get_category_weight(
                category
            )

            if category_weight <= 0:
                continue

            category_score = self.calculate_category_score(
                category
            )

            weighted_score += (

                category_score

                * category_weight

            )

            total_weight += category_weight

        if total_weight == 0:
            return 100.0

        return round(

            clamp_score(

                weighted_score / total_weight

            ),

            2

        )


    # ------------------------------------------------------
    # Windows / Network Score
    # ------------------------------------------------------

    def calculate_windows_score(self) -> float:
        """
        Returns Windows Audit score.
        """

        return self.calculate_module_score(
            MODULE["WINDOWS"]
        )


    def calculate_network_score(self) -> float:
        """
        Returns Network Audit score.
        """

        return self.calculate_module_score(
            MODULE["NETWORK"]
        )


    # ------------------------------------------------------
    # Overall Security Score
    # ------------------------------------------------------

    def calculate_overall_score(self) -> float:
        """
        Calculate overall security score.
        """

        windows_score = self.calculate_windows_score()

        network_score = self.calculate_network_score()

        windows_weight = get_module_weight(
            MODULE["WINDOWS"]
        )

        network_weight = get_module_weight(
            MODULE["NETWORK"]
        )

        total_weight = (

            windows_weight

            +

            network_weight

        )

        if total_weight == 0:
            return 100.0

        overall_score = (

            (

                windows_score

                * windows_weight

            )

            +

            (

                network_score

                * network_weight

            )

        ) / total_weight

        return round(

            clamp_score(overall_score),

            2

        )
        # ------------------------------------------------------
    # Security Posture
    # ------------------------------------------------------

    def get_security_posture(self) -> dict:
        """
        Returns security posture based on
        the overall security score.
        """

        score = self.calculate_overall_score()

        return get_security_posture(score)


    # ------------------------------------------------------
    # Summary
    # ------------------------------------------------------

    def calculate_summary(self) -> dict:
        """
        Returns complete security summary.
        """

        windows_score = self.calculate_windows_score()

        network_score = self.calculate_network_score()

        overall_score = self.calculate_overall_score()

        posture = self.get_security_posture()

        return {

            "windows_score": windows_score,

            "network_score": network_score,

            "overall_score": overall_score,

            "security_posture": posture["name"],

            "posture_color": posture["color"]

        }


    # ------------------------------------------------------
    # Overall Statistics
    # ------------------------------------------------------

    def get_statistics(self) -> dict:
        """
        Returns overall scan statistics.
        """

        stats = {

            "total": 0,

            "passed": 0,

            "warning": 0,

            "critical": 0,

            "information": 0,

            "not_scanned": 0

        }

        for scanner in SCANNER_METADATA:

            status = self.get_status(scanner)

            stats["total"] += 1

            if status == STATUS["PASSED"]:

                stats["passed"] += 1

            elif status == STATUS["WARNING"]:

                stats["warning"] += 1

            elif status == STATUS["CRITICAL"]:

                stats["critical"] += 1

            elif status == STATUS["INFORMATION"]:

                stats["information"] += 1

            else:

                stats["not_scanned"] += 1

        return stats


    # ------------------------------------------------------
    # Category Statistics
    # ------------------------------------------------------

    def get_category_statistics(
        self,
        category: str
    ) -> dict:
        """
        Returns statistics for a category.
        """

        scanners = self.get_category_scanners(
            category
        )

        stats = {

            "total": len(scanners),

            "passed": 0,

            "warning": 0,

            "critical": 0,

            "information": 0,

            "not_scanned": 0

        }

        for scanner in scanners:

            status = self.get_status(scanner)

            if status == STATUS["PASSED"]:

                stats["passed"] += 1

            elif status == STATUS["WARNING"]:

                stats["warning"] += 1

            elif status == STATUS["CRITICAL"]:

                stats["critical"] += 1

            elif status == STATUS["INFORMATION"]:

                stats["information"] += 1

            else:

                stats["not_scanned"] += 1

        stats["score"] = self.calculate_category_score(
            category
        )

        return stats
        # ------------------------------------------------------
    # Scanner Lists
    # ------------------------------------------------------

    def get_passed_scanners(self) -> List[str]:
        """
        Returns all passed scanners.
        """

        return [

            scanner

            for scanner in SCANNER_METADATA

            if self.get_status(scanner)

            == STATUS["PASSED"]

        ]


    def get_warning_scanners(self) -> List[str]:
        """
        Returns all warning scanners.
        """

        return [

            scanner

            for scanner in SCANNER_METADATA

            if self.get_status(scanner)

            == STATUS["WARNING"]

        ]


    def get_critical_scanners(self) -> List[str]:
        """
        Returns all critical scanners.
        """

        return [

            scanner

            for scanner in SCANNER_METADATA

            if self.get_status(scanner)

            == STATUS["CRITICAL"]

        ]


    def get_information_scanners(self) -> List[str]:
        """
        Returns all informational scanners.
        """

        return [

            scanner

            for scanner in SCANNER_METADATA

            if self.get_status(scanner)

            == STATUS["INFORMATION"]

        ]


    def get_not_scanned_scanners(self) -> List[str]:
        """
        Returns all scanners that
        have not been scanned yet.
        """

        return [

            scanner

            for scanner in SCANNER_METADATA

            if self.get_status(scanner)

            == STATUS["NOT_SCANNED"]

        ]


    # ------------------------------------------------------
    # Module Statistics
    # ------------------------------------------------------

    def get_module_statistics(
        self,
        module: str
    ) -> dict:
        """
        Returns statistics for a module.
        """

        categories = self.get_module_categories(
            module
        )

        stats = {

            "module": module,

            "score": self.calculate_module_score(
                module
            ),

            "categories": len(categories),

            "total": 0,

            "passed": 0,

            "warning": 0,

            "critical": 0,

            "information": 0,

            "not_scanned": 0

        }

        for category in categories:

            category_stats = self.get_category_statistics(
                category
            )

            stats["total"] += category_stats["total"]

            stats["passed"] += category_stats["passed"]

            stats["warning"] += category_stats["warning"]

            stats["critical"] += category_stats["critical"]

            stats["information"] += category_stats["information"]

            stats["not_scanned"] += category_stats["not_scanned"]

        return stats


    # ------------------------------------------------------
    # Reset Engine
    # ------------------------------------------------------

    def reset(self) -> None:
        """
        Clears all scan results.
        """

        self.clear()


# ==========================================================
# GLOBAL ENGINE
# ==========================================================

score_engine = SecurityScoreEngine()