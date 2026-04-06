package io.qamelo.secrets.infra.vault;

import io.qamelo.secrets.domain.error.SecretsErrorCode;
import io.qamelo.secrets.domain.error.SecretsException;
import io.qamelo.secrets.domain.spi.SshEngine;
import io.qamelo.secrets.domain.ssh.SshOtpRequest;
import io.qamelo.secrets.domain.ssh.SshOtpResponse;
import io.qamelo.secrets.domain.ssh.SshSignRequest;
import io.qamelo.secrets.domain.ssh.SshSignResponse;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class SshVaultClient implements SshEngine {

    private static final Logger LOG = Logger.getLogger(SshVaultClient.class);

    @Inject
    VaultHttpClient vault;

    @Inject
    VaultConfig config;

    @Override
    public Uni<SshSignResponse> signPublicKey(SshSignRequest request) {
        String path = config.mount().ssh() + "/sign/" + request.roleName();
        JsonObject body = new JsonObject().put("public_key", request.publicKey());
        return vault.post(path, body).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            JsonObject data = new JsonObject(resp.bodyAsString()).getJsonObject("data");
            return new SshSignResponse(data.getString("signed_key"));
        });
    }

    @Override
    public Uni<SshOtpResponse> generateOtp(SshOtpRequest request) {
        String path = config.mount().ssh() + "/creds/" + request.roleName();
        JsonObject body = new JsonObject().put("ip", request.ip());
        return vault.post(path, body).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            JsonObject data = new JsonObject(resp.bodyAsString()).getJsonObject("data");
            return new SshOtpResponse(data.getString("key"), data.getString("username"));
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
