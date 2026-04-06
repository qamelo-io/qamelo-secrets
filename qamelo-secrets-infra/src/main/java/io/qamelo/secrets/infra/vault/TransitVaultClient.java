package io.qamelo.secrets.infra.vault;

import io.qamelo.secrets.domain.error.SecretsErrorCode;
import io.qamelo.secrets.domain.error.SecretsException;
import io.qamelo.secrets.domain.spi.TransitEngine;
import io.qamelo.secrets.domain.transit.DecryptRequest;
import io.qamelo.secrets.domain.transit.DecryptResponse;
import io.qamelo.secrets.domain.transit.EncryptRequest;
import io.qamelo.secrets.domain.transit.EncryptResponse;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class TransitVaultClient implements TransitEngine {

    private static final Logger LOG = Logger.getLogger(TransitVaultClient.class);

    @Inject
    VaultHttpClient vault;

    @Inject
    VaultConfig config;

    @Override
    public Uni<EncryptResponse> encrypt(EncryptRequest request) {
        String path = config.mount().transit() + "/encrypt/" + request.keyName();
        JsonObject body = new JsonObject().put("plaintext", request.plaintext());
        return vault.post(path, body).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            JsonObject data = new JsonObject(resp.bodyAsString()).getJsonObject("data");
            return new EncryptResponse(data.getString("ciphertext"));
        });
    }

    @Override
    public Uni<DecryptResponse> decrypt(DecryptRequest request) {
        String path = config.mount().transit() + "/decrypt/" + request.keyName();
        JsonObject body = new JsonObject().put("ciphertext", request.ciphertext());
        return vault.post(path, body).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            JsonObject data = new JsonObject(resp.bodyAsString()).getJsonObject("data");
            return new DecryptResponse(data.getString("plaintext"));
        });
    }

    private void checkVaultError(int statusCode, String body, String path) {
        if (statusCode >= 200 && statusCode < 300) {
            return;
        }
        SecretsErrorCode code = switch (statusCode) {
            case 400 -> SecretsErrorCode.INVALID_REQUEST;
            case 403 -> SecretsErrorCode.ACCESS_DENIED;
            case 404 -> SecretsErrorCode.SECRET_NOT_FOUND;
            case 429 -> SecretsErrorCode.RATE_LIMITED;
            case 503 -> SecretsErrorCode.VAULT_UNAVAILABLE;
            default -> SecretsErrorCode.UPSTREAM_ERROR;
        };
        LOG.warnf("Vault error on path %s: %d %s", path, statusCode, body);
        throw new SecretsException(code, "Vault error at path " + path + ": " + statusCode);
    }
}
