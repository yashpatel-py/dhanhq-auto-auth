"""Shared Dhan authentication for every strategy under strategy_by_ai/.

    from yash_dhan_auth import get_valid_token_with_retry
    cid, token = get_valid_token_with_retry()

See README.md in this directory for the full recipe.
"""
from .token_manager import (          # noqa: F401
    CREDS_FILE,
    TOKEN_FILE,
    generate_token,
    renew_token,
    validate_token,
    get_valid_token,
    get_valid_token_with_retry,
)
