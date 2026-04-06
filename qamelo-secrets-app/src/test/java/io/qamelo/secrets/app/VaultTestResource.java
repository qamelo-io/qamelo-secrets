package io.qamelo.secrets.app;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import org.testcontainers.vault.VaultContainer;

import java.util.Map;

public class VaultTestResource implements QuarkusTestResourceLifecycleManager {

    public static final String VAULT_TOKEN = "root-test-token";

    public static final VaultContainer<?> VAULT = new VaultContainer<>("hashicorp/vault:1.17.2")
            .withVaultToken(VAULT_TOKEN)
            .withInitCommand(
                    "secrets enable -path=kv kv-v2",
                    "secrets enable -path=pki pki");

    @Override
    public Map<String, String> start() {
        VAULT.start();
        return Map.of(
                "qamelo.vault.url", "http://" + VAULT.getHost() + ":" + VAULT.getFirstMappedPort(),
                "qamelo.vault.auth.method", "token",
                "qamelo.vault.auth.token", VAULT_TOKEN,
                "qamelo.vault.mount.kv", "kv",
                "qamelo.vault.mount.pki", "pki",
                "qamelo.internal.secret", "test-secret",
                "quarkus.http.auth.proactive", "false"
        );
    }

    @Override
    public void stop() {
        VAULT.stop();
    }
}
