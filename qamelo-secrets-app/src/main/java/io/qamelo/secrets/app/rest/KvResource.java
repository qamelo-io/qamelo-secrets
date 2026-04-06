package io.qamelo.secrets.app.rest;

import io.qamelo.secrets.domain.kv.KvMetadata;
import io.qamelo.secrets.domain.kv.KvSecret;
import io.qamelo.secrets.domain.kv.KvWriteResult;
import io.qamelo.secrets.domain.spi.SecretStore;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;

import java.util.Map;

@Path("/api/v1/internal/secrets/kv")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class KvResource {

    @Inject
    SecretStore secretStore;

    @GET
    @Path("{path: .+}/metadata")
    public Uni<KvMetadata> readMetadata(@PathParam("path") String path) {
        return secretStore.readMetadata(path);
    }

    @GET
    @Path("{path: .+}")
    public Uni<KvSecret> read(@PathParam("path") String path,
                              @QueryParam("version") Integer version) {
        if (version != null) {
            return secretStore.read(path, version);
        }
        return secretStore.read(path);
    }

    @PUT
    @Path("{path: .+}")
    public Uni<KvWriteResult> write(@PathParam("path") String path,
                                    @QueryParam("cas") Integer cas,
                                    WriteRequest body) {
        if (cas != null) {
            return secretStore.write(path, body.data(), cas);
        }
        return secretStore.write(path, body.data());
    }

    @DELETE
    @Path("{path: .+}")
    public Uni<Void> delete(@PathParam("path") String path) {
        return secretStore.delete(path);
    }

    public record WriteRequest(Map<String, String> data) {
    }
}
