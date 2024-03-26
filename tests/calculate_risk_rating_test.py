"""Unittests for calculating risk rating."""

import pytest

from agent import osv_output_handler


@pytest.mark.parametrize(
    "risk_ratings, expected_rating",
    [
        ([], "POTENTIALLY"),
        (["HIGH"], "HIGH"),
        (["HIGH", "MEDIUM"], "HIGH"),
        (["HIGH", "MEDIUM", "LOW"], "HIGH"),
        (["MEDIUM", "HIGH"], "HIGH"),
        (["LOW", "HIGH", "MEDIUM"], "HIGH"),
        (["MEDIUM", "LOW"], "MEDIUM"),
        (["LOW"], "LOW"),
        (["LOW", "LOW", "LOW"], "LOW"),
        (["high"], "HIGH"),
        (["x"], "POTENTIALLY"),
        (["x", "high"], "HIGH"),
        (["MEDIUM", "HIGH", "CRITICAL"], "CRITICAL"),
    ],
)
def testCalculateRiskRating_whenCveRiskRating_returnRiskRating(
    risk_ratings: list[str], expected_rating: str
) -> None:
    assert osv_output_handler.calculate_risk_rating(risk_ratings) == expected_rating
