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
                    "secrets enable -path=pki pki",
                    "secrets enable -path=transit transit",
                    "secrets enable -path=ssh-client-signer ssh",
                    "secrets enable -path=database database");

    @Override
    public Map<String, String> start() {
        VAULT.start();
        var props = new java.util.HashMap<String, String>();
        props.put("qamelo.vault.url", "http://" + VAULT.getHost() + ":" + VAULT.getFirstMappedPort());
        props.put("qamelo.vault.auth.method", "token");
        props.put("qamelo.vault.auth.token", VAULT_TOKEN);
        props.put("qamelo.vault.mount.kv", "kv");
        props.put("qamelo.vault.mount.pki", "pki");
        props.put("qamelo.vault.mount.transit", "transit");
        props.put("qamelo.vault.mount.ssh", "ssh-client-signer");
        props.put("qamelo.vault.mount.database", "database");
        props.put("qamelo.internal.secret", "test-secret");
        props.put("quarkus.http.auth.proactive", "false");
        return props;
    }

    @Override
    public void stop() {
        VAULT.stop();
    }
}
