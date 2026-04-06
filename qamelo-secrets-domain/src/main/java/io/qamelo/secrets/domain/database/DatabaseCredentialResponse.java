package io.qamelo.secrets.domain.database;

public record DatabaseCredentialResponse(
        String username,
        String password,
        String leaseId,
        long leaseDuration,
        boolean renewable) {
}
