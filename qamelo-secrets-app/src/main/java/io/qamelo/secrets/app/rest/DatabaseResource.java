package io.qamelo.secrets.app.rest;

import io.qamelo.secrets.domain.database.DatabaseCredentialResponse;
import io.qamelo.secrets.domain.database.LeaseRenewRequest;
import io.qamelo.secrets.domain.database.LeaseRenewResponse;
import io.qamelo.secrets.domain.spi.DatabaseCredentialStore;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;

@Path("/api/v1/internal/secrets/database")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class DatabaseResource {

    @Inject
    DatabaseCredentialStore databaseStore;

    @POST
    @Path("creds/{role}")
    public Uni<DatabaseCredentialResponse> generateCredentials(@PathParam("role") String role) {
        return databaseStore.generateCredentials(role);
    }

    @POST
    @Path("leases/renew")
    public Uni<LeaseRenewResponse> renewLease(LeaseRenewRequest request) {
        return databaseStore.renewLease(request);
    }

    @POST
    @Path("leases/revoke")
    public Uni<Void> revokeLease(RevokeLeaseRequest request) {
        return databaseStore.revokeLease(request.leaseId());
    }

    public record RevokeLeaseRequest(String leaseId) {
    }
}
