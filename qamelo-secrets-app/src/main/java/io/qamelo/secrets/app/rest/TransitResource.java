package io.qamelo.secrets.app.rest;

import io.qamelo.secrets.domain.spi.TransitEngine;
import io.qamelo.secrets.domain.transit.DecryptRequest;
import io.qamelo.secrets.domain.transit.DecryptResponse;
import io.qamelo.secrets.domain.transit.EncryptRequest;
import io.qamelo.secrets.domain.transit.EncryptResponse;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

@Path("/api/v1/internal/secrets/transit")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class TransitResource {

    @Inject
    TransitEngine transitEngine;

    @POST
    @Path("encrypt")
    public Uni<EncryptResponse> encrypt(EncryptRequest request) {
        return transitEngine.encrypt(request);
    }

    @POST
    @Path("decrypt")
    public Uni<DecryptResponse> decrypt(DecryptRequest request) {
        return transitEngine.decrypt(request);
    }
}
