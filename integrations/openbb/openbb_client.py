import logging

logger = logging.getLogger(__name__)


def get_company_profile(ticker: str) -> dict:
    """Fetch company profile via OpenBB (falls back to yfinance if OpenBB not configured)."""

    try:
        from openbb import obb
        result = obb.equity.profile(symbol=ticker, provider="yfinance")
        if result and result.results:
            r = result.results[0]
            return {
                "name":        getattr(r, "name", ticker),
                "sector":      getattr(r, "sector", ""),
                "industry":    getattr(r, "industry", ""),
                "market_cap":  getattr(r, "market_cap", None),
                "employees":   getattr(r, "full_time_employees", None),
                "website":     getattr(r, "website", ""),
                "description": getattr(r, "description", "")[:500],
                "source":      "openbb",
            }
    except ImportError:
        logger.debug("OpenBB not installed — trying yfinance directly")
    except Exception as e:
        logger.warning("OpenBB profile fetch failed for %s: %s", ticker, e)

    try:
        import yfinance as yf
        info = yf.Ticker(ticker).info
        return {
            "name":        info.get("longName", ticker),
            "sector":      info.get("sector", ""),
            "industry":    info.get("industry", ""),
            "market_cap":  info.get("marketCap"),
            "employees":   info.get("fullTimeEmployees"),
            "website":     info.get("website", ""),
            "description": info.get("longBusinessSummary", "")[:500],
            "source":      "yfinance",
        }
    except ImportError:
        logger.debug("yfinance not installed — returning stub profile")
    except Exception as e:
        logger.warning("yfinance profile fetch failed for %s: %s", ticker, e)

    return {
        "name": ticker, "sector": "", "industry": "",
        "market_cap": None, "employees": None,
        "website": "", "description": "", "source": "unavailable",
    }


def get_financial_summary(ticker: str) -> dict:
    """Return basic financial context — market cap, sector, description."""
    profile = get_company_profile(ticker)
    market_cap = profile.get("market_cap")

    if market_cap:
        if market_cap >= 1_000_000_000_000:
            cap_label = f"${market_cap / 1_000_000_000_000:.1f}T"
        elif market_cap >= 1_000_000_000:
            cap_label = f"${market_cap / 1_000_000_000:.1f}B"
        else:
            cap_label = f"${market_cap / 1_000_000:.0f}M"
    else:
        cap_label = "N/A"

    return {
        "ticker":      ticker.upper(),
        "name":        profile.get("name"),
        "sector":      profile.get("sector"),
        "industry":    profile.get("industry"),
        "market_cap":  cap_label,
        "employees":   profile.get("employees"),
        "website":     profile.get("website"),
        "description": profile.get("description"),
        "data_source": profile.get("source"),
    }
