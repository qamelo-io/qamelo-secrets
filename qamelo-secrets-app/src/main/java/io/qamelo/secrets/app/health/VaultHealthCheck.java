package io.qamelo.secrets.app.health;

import io.qamelo.secrets.infra.vault.VaultHttpClient;
import io.smallrye.health.api.AsyncHealthCheck;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Readiness;

@Readiness
@ApplicationScoped
public class VaultHealthCheck implements AsyncHealthCheck {

    @Inject
    VaultHttpClient vaultHttpClient;

    @Override
    public Uni<HealthCheckResponse> call() {
        return vaultHttpClient.healthCheck()
                .map(resp -> {
                    if (resp.statusCode() == 200) {
                        return HealthCheckResponse.named("Vault")
                                .up()
                                .withData("status", "CONNECTED")
                                .build();
                    }
                    return HealthCheckResponse.named("Vault")
                            .down()
                            .withData("status", "UNHEALTHY")
                            .withData("http_status", resp.statusCode())
                            .build();
                })
                .onFailure().recoverWithItem(err ->
                        HealthCheckResponse.named("Vault")
                                .down()
                                .withData("status", "UNREACHABLE")
                                .withData("error", err.getMessage())
                                .build());
    }
}
