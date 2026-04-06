package io.qamelo.secrets.domain.database;

public record LeaseRenewRequest(String leaseId, long increment) {
}
