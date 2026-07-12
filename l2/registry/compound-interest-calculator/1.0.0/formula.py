"""Deterministic compound-interest formula (L2 reference implementation).

This is a *pure function*: no I/O, no clock, no network, no randomness. It is the
executor that the local L2 registry (``l2/registry.py``) resolves for
``(slug="compound-interest-calculator", version="1.0.0")``.

Numeric model (``vcc-decimal-v1``):
  * All arithmetic is done in :class:`decimal.Decimal` at high precision so the
    calculation is exactly reproducible on any platform (no IEEE-754 drift).
  * Interest is compounded MONTHLY. The monthly rate is ``annualRate / 12``.
  * Contributions are made at the END of each month (ordinary annuity):
    each month the running balance first grows by the monthly rate, then the
    monthly contribution is added.
  * Values are accumulated UNROUNDED and quantized to the declared output scale
    ONLY at the boundary, using banker's rounding (ROUND_HALF_EVEN), matching the
    profile's declared rounding mode.

These rules were derived from — and are pinned by — the golden vector
``vectors/compound-interest-calculator.json``. Do not "fix" the math without
bumping the manifest version; the manifest digest is the formula's identity.
"""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_EVEN, getcontext
from typing import Any, Dict, List

# High working precision. The compounding loop is at most 12 * years iterations
# (schema-bounded), so 60 significant digits is far more than enough to keep the
# accumulation exact relative to the 2-decimal output scale.
getcontext().prec = 60

MONTHS_PER_YEAR = 12

# Declared output scales (mirror the manifest / golden vector).
MONEY_SCALE = Decimal("0.01")   # scale 2


def _q(value: Decimal, quant: Decimal = MONEY_SCALE) -> Decimal:
    """Quantize an unrounded Decimal to the declared scale with half-even."""
    return value.quantize(quant, rounding=ROUND_HALF_EVEN)


def _money(value: Decimal) -> Dict[str, Any]:
    """Emit a canonical `money` typed value (USD, scale 2) as declared strings."""
    return {"type": "money", "value": str(_q(value)), "scale": 2, "unit": "USD"}


def _integer(value: int) -> Dict[str, Any]:
    return {"type": "integer", "value": str(int(value)), "scale": 0}


def compute(inputs: Dict[str, Decimal]) -> Dict[str, Any]:
    """Run the compound-interest calculation on decoded Decimal inputs.

    Parameters
    ----------
    inputs:
        A mapping with Decimal values for keys:
          - ``initialPrincipal``  (money)
          - ``monthlyContribution`` (money)
          - ``annualRatePct``     (percent, e.g. Decimal("6.0000") means 6%)
          - ``years``             (duration, whole years as a Decimal)

    Returns
    -------
    A dict of canonical typed-value outputs exactly shaped like the statement's
    ``calculation.outputs`` block:
      ``finalBalance``, ``totalContributed``, ``totalInterest``, ``yearlyTable``.
    """
    principal = Decimal(inputs["initialPrincipal"])
    monthly_contribution = Decimal(inputs["monthlyContribution"])
    annual_rate_pct = Decimal(inputs["annualRatePct"])
    years = int(Decimal(inputs["years"]))  # whole years

    # Percent -> fraction, then per-month rate.
    annual_rate = annual_rate_pct / Decimal(100)
    monthly_rate = annual_rate / Decimal(MONTHS_PER_YEAR)

    balance = principal
    yearly_table: List[Dict[str, Any]] = []

    total_months = MONTHS_PER_YEAR * years
    for month in range(1, total_months + 1):
        # Grow first, then contribute at end of month (ordinary annuity).
        balance = balance * (Decimal(1) + monthly_rate)
        balance = balance + monthly_contribution

        if month % MONTHS_PER_YEAR == 0:
            year = month // MONTHS_PER_YEAR
            contributed = principal + monthly_contribution * (MONTHS_PER_YEAR * year)
            interest = balance - contributed
            yearly_table.append(
                {
                    "year": _integer(year),
                    "balance": _money(balance),
                    "contributed": _money(contributed),
                    "interest": _money(interest),
                }
            )

    total_contributed = principal + monthly_contribution * (MONTHS_PER_YEAR * years)
    total_interest = balance - total_contributed

    return {
        "finalBalance": _money(balance),
        "totalContributed": _money(total_contributed),
        "totalInterest": _money(total_interest),
        "yearlyTable": yearly_table,
    }
