package io.qamelo.secrets.infra.vault;

import io.qamelo.secrets.domain.error.SecretsErrorCode;
import io.qamelo.secrets.domain.error.SecretsException;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;
import io.vertx.mutiny.ext.web.client.HttpResponse;
import io.vertx.mutiny.ext.web.client.WebClient;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.net.URI;

@ApplicationScoped
public class VaultHttpClient {

    private static final Logger LOG = Logger.getLogger(VaultHttpClient.class);

    @Inject
    Vertx vertx;

    @Inject
    VaultConfig config;

    private WebClient client;
    private String vaultToken;
    private long renewalTimerId = -1;

    @PostConstruct
    void init() {
        URI uri = URI.create(config.url());
        client = WebClient.create(vertx, new WebClientOptions()
                .setDefaultHost(uri.getHost())
                .setDefaultPort(uri.getPort() == -1 ? 8200 : uri.getPort())
                .setSsl("https".equals(uri.getScheme())));

        if ("token".equals(config.auth().method())) {
            vaultToken = config.auth().token().orElseThrow(() ->
                    new IllegalStateException("qamelo.vault.auth.token required when auth.method=token"));
            LOG.info("Vault auth: using static token (dev/test mode)");
        } else {
            loginKubernetes();
        }
    }

    @PreDestroy
    void cleanup() {
        if (renewalTimerId >= 0) {
            vertx.cancelTimer(renewalTimerId);
        }
        if (client != null) {
            client.close();
        }
    }

    public Uni<HttpResponse<Buffer>> get(String path) {
        return client.get("/v1/" + path)
                .putHeader("X-Vault-Token", vaultToken)
                .send()
                .invoke(resp -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.tracef("GET /v1/%s -> %d", path, resp.statusCode());
                    }
                });
    }

    public Uni<HttpResponse<Buffer>> post(String path, JsonObject body) {
        return client.post("/v1/" + path)
                .putHeader("X-Vault-Token", vaultToken)
                .putHeader("Content-Type", "application/json")
                .sendBuffer(Buffer.buffer(body.encode()))
                .invoke(resp -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.tracef("POST /v1/%s -> %d", path, resp.statusCode());
                    }
                });
    }

    public Uni<HttpResponse<Buffer>> put(String path, JsonObject body) {
        return client.put("/v1/" + path)
                .putHeader("X-Vault-Token", vaultToken)
                .putHeader("Content-Type", "application/json")
                .sendBuffer(Buffer.buffer(body.encode()))
                .invoke(resp -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.tracef("PUT /v1/%s -> %d", path, resp.statusCode());
                    }
                });
    }

    public Uni<HttpResponse<Buffer>> delete(String path) {
        return client.delete("/v1/" + path)
                .putHeader("X-Vault-Token", vaultToken)
                .send()
                .invoke(resp -> {
                    if (LOG.isTraceEnabled()) {
                        LOG.tracef("DELETE /v1/%s -> %d", path, resp.statusCode());
                    }
                });
    }

    public Uni<HttpResponse<Buffer>> healthCheck() {
        return client.get("/v1/sys/health")
                .putHeader("X-Vault-Token", vaultToken)
                .send();
    }

    private void loginKubernetes() {
        try {
            String jwt = java.nio.file.Files.readString(
                    java.nio.file.Path.of("/var/run/secrets/kubernetes.io/serviceaccount/token"));
            String role = config.auth().kubernetes().role();

            JsonObject body = new JsonObject()
                    .put("jwt", jwt)
                    .put("role", role);

            client.post("/v1/auth/kubernetes/login")
                    .putHeader("Content-Type", "application/json")
                    .sendBuffer(Buffer.buffer(body.encode()))
                    .subscribe().with(
                            resp -> {
                                if (resp.statusCode() == 200) {
                                    JsonObject authData = new JsonObject(resp.bodyAsString()).getJsonObject("auth");
                                    vaultToken = authData.getString("client_token");
                                    int leaseDuration = authData.getInteger("lease_duration", 3600);
                                    scheduleRenewal(leaseDuration);
                                    LOG.infof("Vault K8s auth successful, token TTL: %ds", leaseDuration);
                                } else {
                                    LOG.errorf("Vault K8s auth failed: %d %s", resp.statusCode(), resp.bodyAsString());
                                    throw new SecretsException(SecretsErrorCode.VAULT_UNAVAILABLE,
                                            "Vault K8s auth failed: " + resp.statusCode());
                                }
                            },
                            err -> {
                                LOG.errorf("Vault K8s auth error: %s", err.getMessage());
                                throw new SecretsException(SecretsErrorCode.VAULT_UNAVAILABLE,
                                        "Vault K8s auth error: " + err.getMessage(), err);
                            }
                    );
        } catch (java.io.IOException e) {
            throw new SecretsException(SecretsErrorCode.VAULT_UNAVAILABLE,
                    "Cannot read ServiceAccount token: " + e.getMessage(), e);
        }
    }

    private void scheduleRenewal(int leaseDurationSeconds) {
        long renewalMs = (long) (leaseDurationSeconds * 0.75 * 1000);
        renewalTimerId = vertx.setPeriodic(renewalMs, id -> renewToken());
    }

    private void renewToken() {
        client.post("/v1/auth/token/renew-self")
                .putHeader("X-Vault-Token", vaultToken)
                .putHeader("Content-Type", "application/json")
                .sendBuffer(Buffer.buffer("{}"))
                .subscribe().with(
                        resp -> {
                            if (resp.statusCode() == 200) {
                                LOG.debug("Vault token renewed successfully");
                            } else {
                                LOG.warnf("Vault token renewal failed: %d", resp.statusCode());
                                loginKubernetes();
                            }
                        },
                        err -> {
                            LOG.warnf("Vault token renewal error: %s", err.getMessage());
                            loginKubernetes();
                        }
                );
    }
}
