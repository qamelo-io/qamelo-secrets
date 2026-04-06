package io.qamelo.secrets.infra.vault;

import io.qamelo.secrets.domain.error.SecretsErrorCode;
import io.qamelo.secrets.domain.error.SecretsException;
import io.qamelo.secrets.domain.kv.KvMetadata;
import io.qamelo.secrets.domain.kv.KvSecret;
import io.qamelo.secrets.domain.kv.KvVersionInfo;
import io.qamelo.secrets.domain.kv.KvWriteResult;
import io.qamelo.secrets.domain.spi.SecretStore;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@ApplicationScoped
public class KvVaultClient implements SecretStore {

    private static final Logger LOG = Logger.getLogger(KvVaultClient.class);

    @Inject
    VaultHttpClient vault;

    @Inject
    VaultConfig config;

    @Override
    public Uni<KvSecret> read(String path) {
        String vaultPath = config.mount().kv() + "/data/" + path;
        return vault.get(vaultPath).map(resp -> {
            if (resp.statusCode() == 404) {
                throw new SecretsException(SecretsErrorCode.SECRET_NOT_FOUND,
                        "No secret exists at path " + path);
            }
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            return parseKvSecret(resp.bodyAsString());
        });
    }

    @Override
    public Uni<KvSecret> read(String path, int version) {
        String vaultPath = config.mount().kv() + "/data/" + path + "?version=" + version;
        return vault.get(vaultPath).map(resp -> {
            if (resp.statusCode() == 404) {
                throw new SecretsException(SecretsErrorCode.SECRET_NOT_FOUND,
                        "No secret exists at path " + path + " version " + version);
            }
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            return parseKvSecret(resp.bodyAsString());
        });
    }

    @Override
    public Uni<KvWriteResult> write(String path, Map<String, String> data) {
        String vaultPath = config.mount().kv() + "/data/" + path;
        JsonObject body = new JsonObject().put("data", new JsonObject(new HashMap<>(data)));
        return vault.post(vaultPath, body).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            return parseWriteResult(resp.bodyAsString());
        });
    }

    @Override
    public Uni<KvWriteResult> write(String path, Map<String, String> data, int cas) {
        String vaultPath = config.mount().kv() + "/data/" + path;
        JsonObject options = new JsonObject().put("cas", cas);
        JsonObject body = new JsonObject()
                .put("options", options)
                .put("data", new JsonObject(new HashMap<>(data)));
        return vault.post(vaultPath, body).map(resp -> {
            if (resp.statusCode() == 400) {
                String responseBody = resp.bodyAsString();
                if (responseBody != null && responseBody.contains("check-and-set")) {
                    throw new SecretsException(SecretsErrorCode.INVALID_REQUEST,
                            "CAS conflict: current version does not match cas=" + cas);
                }
            }
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            return parseWriteResult(resp.bodyAsString());
        });
    }

    @Override
    public Uni<Void> delete(String path) {
        String vaultPath = config.mount().kv() + "/data/" + path;
        return vault.delete(vaultPath).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            return null;
        });
    }

    @Override
    public Uni<KvMetadata> readMetadata(String path) {
        String vaultPath = config.mount().kv() + "/metadata/" + path;
        return vault.get(vaultPath).map(resp -> {
            if (resp.statusCode() == 404) {
                throw new SecretsException(SecretsErrorCode.SECRET_NOT_FOUND,
                        "No metadata exists at path " + path);
            }
            checkVaultError(resp.statusCode(), resp.bodyAsString(), path);
            return parseMetadata(resp.bodyAsString());
        });
    }

    private KvSecret parseKvSecret(String body) {
        JsonObject json = new JsonObject(body);
        JsonObject data = json.getJsonObject("data");
        JsonObject secretData = data.getJsonObject("data");
        JsonObject metadata = data.getJsonObject("metadata");

        Map<String, String> dataMap = new HashMap<>();
        if (secretData != null) {
            secretData.forEach(entry -> dataMap.put(entry.getKey(), String.valueOf(entry.getValue())));
        }

        int version = metadata.getInteger("version", 0);
        Instant createdTime = parseInstant(metadata.getString("created_time"));

        return new KvSecret(dataMap, version, createdTime);
    }

    private KvWriteResult parseWriteResult(String body) {
        JsonObject json = new JsonObject(body);
        JsonObject data = json.getJsonObject("data");
        int version = data.getInteger("version", 0);
        Instant createdTime = parseInstant(data.getString("created_time"));
        return new KvWriteResult(version, createdTime);
    }

    private KvMetadata parseMetadata(String body) {
        JsonObject json = new JsonObject(body);
        JsonObject data = json.getJsonObject("data");
        int currentVersion = data.getInteger("current_version", 0);
        Instant createdTime = parseInstant(data.getString("created_time"));
        Instant updatedTime = parseInstant(data.getString("updated_time"));

        Map<Integer, KvVersionInfo> versions = new HashMap<>();
        JsonObject versionsJson = data.getJsonObject("versions");
        if (versionsJson != null) {
            versionsJson.forEach(entry -> {
                int ver = Integer.parseInt(entry.getKey());
                JsonObject vInfo = (JsonObject) entry.getValue();
                versions.put(ver, new KvVersionInfo(
                        ver,
                        parseInstant(vInfo.getString("created_time")),
                        parseInstant(vInfo.getString("deletion_time")),
                        vInfo.getBoolean("destroyed", false)));
            });
        }

        return new KvMetadata(currentVersion, createdTime, updatedTime, versions);
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

    private Instant parseInstant(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            return null;
        }
    }
}
