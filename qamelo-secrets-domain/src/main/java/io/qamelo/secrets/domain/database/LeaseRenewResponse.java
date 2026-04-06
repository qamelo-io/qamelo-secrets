package io.qamelo.secrets.domain.database;

public record LeaseRenewResponse(String leaseId, long leaseDuration, boolean renewable) {
}
