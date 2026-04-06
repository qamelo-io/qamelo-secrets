package io.qamelo.secrets.domain.spi;

import io.qamelo.secrets.domain.database.DatabaseCredentialResponse;
import io.qamelo.secrets.domain.database.LeaseRenewRequest;
import io.qamelo.secrets.domain.database.LeaseRenewResponse;
import io.smallrye.mutiny.Uni;

/**
 * Database secret engine — dynamic JDBC credentials with lease TTL.
 */
public interface DatabaseCredentialStore {

    Uni<DatabaseCredentialResponse> generateCredentials(String role);

    Uni<LeaseRenewResponse> renewLease(LeaseRenewRequest request);

    Uni<Void> revokeLease(String leaseId);
}
