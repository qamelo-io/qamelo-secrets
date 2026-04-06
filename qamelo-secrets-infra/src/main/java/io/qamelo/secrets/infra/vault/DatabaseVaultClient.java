package io.qamelo.secrets.infra.vault;

import io.qamelo.secrets.domain.database.DatabaseCredentialResponse;
import io.qamelo.secrets.domain.database.LeaseRenewRequest;
import io.qamelo.secrets.domain.database.LeaseRenewResponse;
import io.qamelo.secrets.domain.error.SecretsErrorCode;
import io.qamelo.secrets.domain.error.SecretsException;
import io.qamelo.secrets.domain.spi.DatabaseCredentialStore;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class DatabaseVaultClient implements DatabaseCredentialStore {

    private static final Logger LOG = Logger.getLogger(DatabaseVaultClient.class);

    @Inject
    VaultHttpClient vault;

    @Inject
    VaultConfig config;

    @Override
    public Uni<DatabaseCredentialResponse> generateCredentials(String role) {
        String vaultPath = config.mount().database() + "/creds/" + role;
        return vault.get(vaultPath).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), vaultPath);
            return parseCredentialResponse(resp.bodyAsString());
        });
    }

    @Override
    public Uni<LeaseRenewResponse> renewLease(LeaseRenewRequest request) {
        JsonObject body = new JsonObject()
                .put("lease_id", request.leaseId())
                .put("increment", request.increment());
        return vault.put("sys/leases/renew", body).map(resp -> {
            checkLeaseError(resp.statusCode(), resp.bodyAsString(), "sys/leases/renew");
            return parseLeaseRenewResponse(resp.bodyAsString());
        });
    }

    @Override
    public Uni<Void> revokeLease(String leaseId) {
        JsonObject body = new JsonObject()
                .put("lease_id", leaseId);
        return vault.put("sys/leases/revoke", body).map(resp -> {
            checkLeaseError(resp.statusCode(), resp.bodyAsString(), "sys/leases/revoke");
            return null;
        });
    }

    private DatabaseCredentialResponse parseCredentialResponse(String body) {
        JsonObject json = new JsonObject(body);
        JsonObject data = json.getJsonObject("data");
        return new DatabaseCredentialResponse(
                data.getString("username"),
                data.getString("password"),
                json.getString("lease_id"),
                json.getLong("lease_duration", 0L),
                json.getBoolean("renewable", false));
    }

    private LeaseRenewResponse parseLeaseRenewResponse(String body) {
        JsonObject json = new JsonObject(body);
        return new LeaseRenewResponse(
                json.getString("lease_id"),
                json.getLong("lease_duration", 0L),
                json.getBoolean("renewable", false));
    }

    private void checkVaultError(int statusCode, String body, String path) {
        if (statusCode >= 200 && statusCode < 300) {
            return;
        }
        SecretsErrorCode code = switch (statusCode) {
            case 403 -> SecretsErrorCode.ACCESS_DENIED;
            case 404 -> SecretsErrorCode.SECRET_NOT_FOUND;
            case 429 -> SecretsErrorCode.RATE_LIMITED;
            case 503 -> SecretsErrorCode.VAULT_UNAVAILABLE;
            default -> SecretsErrorCode.UPSTREAM_ERROR;
        };
        LOG.warnf("Vault error on path %s: %d %s", path, statusCode, body);
        throw new SecretsException(code, "Vault error at path " + path + ": " + statusCode);
    }

    private void checkLeaseError(int statusCode, String body, String path) {
        if (statusCode >= 200 && statusCode < 300) {
            return;
        }
        if (statusCode == 400) {
            LOG.warnf("Lease error on path %s: %d %s", path, statusCode, body);
            throw new SecretsException(SecretsErrorCode.LEASE_EXPIRED,
                    "Lease not found or expired: " + statusCode);
        }
        checkVaultError(statusCode, body, path);
    }
}
