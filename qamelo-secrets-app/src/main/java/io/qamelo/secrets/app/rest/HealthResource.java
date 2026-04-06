package io.qamelo.secrets.app.rest;

import io.qamelo.secrets.infra.vault.VaultConfig;
import io.qamelo.secrets.infra.vault.VaultHttpClient;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.util.Map;

@Path("/api/v1/internal/secrets/health")
@Produces(MediaType.APPLICATION_JSON)
public class HealthResource {

    @Inject
    VaultHttpClient vaultHttpClient;

    @Inject
    VaultConfig vaultConfig;

    @GET
    public Uni<Map<String, Object>> health() {
        return vaultHttpClient.healthCheck()
                .map(resp -> {
                    if (resp.statusCode() == 200) {
                        return Map.<String, Object>of(
                                "status", "UP",
                                "vault", "CONNECTED",
                                "auth", vaultConfig.auth().method().toUpperCase());
                    }
                    return Map.<String, Object>of(
                            "status", "DOWN",
                            "vault", "UNHEALTHY");
                })
                .onFailure().recoverWithItem(err ->
                        Map.of("status", "DOWN",
                                "vault", "UNREACHABLE",
                                "error", err.getMessage()));
    }
}
