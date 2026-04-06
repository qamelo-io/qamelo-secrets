package io.qamelo.secrets.app.database;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import org.testcontainers.containers.PostgreSQLContainer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

public class DatabaseTestResource implements QuarkusTestResourceLifecycleManager {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Override
    public Map<String, String> start() {
        POSTGRES.start();
        configureVaultDatabase();
        return Map.of();
    }

    @Override
    public void stop() {
        POSTGRES.stop();
    }

    private void configureVaultDatabase() {
        String vaultUrl = "http://" + VaultTestResource.VAULT.getHost() + ":"
                + VaultTestResource.VAULT.getFirstMappedPort();
        String token = VaultTestResource.VAULT_TOKEN;

        // Get the PostgreSQL container's IP on the Docker bridge network
        String pgIp = POSTGRES.getContainerInfo()
                .getNetworkSettings()
                .getNetworks()
                .values()
                .iterator()
                .next()
                .getIpAddress();

        String connectionUrl = "postgresql://{{username}}:{{password}}@" + pgIp + ":5432/test?sslmode=disable";

        try (HttpClient client = HttpClient.newHttpClient()) {
            // Database engine already enabled by VaultTestResource

            // Configure PostgreSQL connection
            vaultRequest(client, vaultUrl, token, "POST",
                    "/v1/database/config/postgresql",
                    """
                    {
                        "plugin_name": "postgresql-database-plugin",
                        "allowed_roles": "test-role",
                        "connection_url": "%s",
                        "username": "%s",
                        "password": "%s"
                    }
                    """.formatted(connectionUrl, POSTGRES.getUsername(), POSTGRES.getPassword()));

            // Create test-role
            vaultRequest(client, vaultUrl, token, "POST",
                    "/v1/database/roles/test-role",
                    """
                    {
                        "db_name": "postgresql",
                        "creation_statements": ["CREATE ROLE \\"{{name}}\\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \\"{{name}}\\";"],
                        "default_ttl": "1h",
                        "max_ttl": "24h"
                    }
                    """);
        } catch (Exception e) {
            throw new RuntimeException("Failed to configure Vault database engine", e);
        }
    }

    private void vaultRequest(HttpClient client, String vaultUrl, String token,
                              String method, String path, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(vaultUrl + path))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() >= 400) {
            throw new RuntimeException("Vault config failed: " + path + " -> "
                    + response.statusCode() + " " + response.body());
        }
    }
}
