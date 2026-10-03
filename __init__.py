"""Shared Dhan authentication for every strategy under strategy_by_ai/.

    from yash_dhan_auth import get_client
    dhan = get_client()                       # dhanhq facade on today's token
    dhan.option_chain(13, "IDX_I", "2026-10-07")

    from yash_dhan_auth import get_valid_token_with_retry
    cid, token = get_valid_token_with_retry()  # raw (client_id, access_token)

See README.md in this directory for the full recipe and the capability table.
"""
from .token_manager import (          # noqa: F401
    CREDS_FILE,
    TOKEN_FILE,
    LOCK_FILE,
    IST,
    TokenError,
    CredentialsRejected,
    LoginCoolingDown,
    TokenMintThrottled,
    DhanUnreachable,
    LoginDisabled,
    login_disabled,
    get_valid_token,
    get_valid_token_with_retry,
    force_refresh,
    get_client,
    get_context,
    market_feed,
    depth_feed,
    rest_headers,
    check_token,
    validate_token,
    account_status,
    data_access,
    token_info,
    token_claims,
    token_type,
    token_expiry,
    generate_token,
    renew_token,
    restrict_permissions,
)
from .capabilities import Capability, check_capabilities, market_open_now   # noqa: F401
