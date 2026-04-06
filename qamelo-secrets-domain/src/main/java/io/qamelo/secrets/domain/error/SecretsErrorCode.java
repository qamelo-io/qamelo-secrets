package io.qamelo.secrets.domain.error;

public enum SecretsErrorCode {

    SECRET_NOT_FOUND,
    ACCESS_DENIED,
    VAULT_UNAVAILABLE,
    LEASE_EXPIRED,
    INVALID_REQUEST,
    RATE_LIMITED,
    UPSTREAM_ERROR
}
