package io.qamelo.secrets.app.transit;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
@QuarkusTestResource(VaultTestResource.class)
class TransitResourceTest {

    @BeforeAll
    static void setupVault() throws Exception {
        String vaultUrl = "http://" + VaultTestResource.VAULT.getHost()
                + ":" + VaultTestResource.VAULT.getFirstMappedPort();

        try (HttpClient client = HttpClient.newHttpClient()) {
            // Create encryption key
            HttpRequest createKey = HttpRequest.newBuilder()
                    .uri(URI.create(vaultUrl + "/v1/transit/keys/test-key"))
                    .header("X-Vault-Token", VaultTestResource.VAULT_TOKEN)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"type\":\"aes256-gcm96\"}"))
                    .build();
            client.send(createKey, HttpResponse.BodyHandlers.ofString());
        }
    }

    @Test
    void encryptReturnsVaultCiphertext() {
        String plaintext = Base64.getEncoder().encodeToString("hello-world".getBytes());

        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("keyName", "test-key", "plaintext", plaintext))
                .when()
                .post("/api/v1/internal/secrets/transit/encrypt")
                .then()
                .statusCode(200)
                .body("ciphertext", startsWith("vault:v1:"));
    }

    @Test
    void decryptReturnsOriginalPlaintext() {
        String plaintext = Base64.getEncoder().encodeToString("roundtrip-test".getBytes());

        // Encrypt first
        String ciphertext = given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("keyName", "test-key", "plaintext", plaintext))
                .when()
                .post("/api/v1/internal/secrets/transit/encrypt")
                .then()
                .statusCode(200)
                .extract()
                .path("ciphertext");

        // Decrypt
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("keyName", "test-key", "ciphertext", ciphertext))
                .when()
                .post("/api/v1/internal/secrets/transit/decrypt")
                .then()
                .statusCode(200)
                .body("plaintext", equalTo(plaintext));
    }

    @Test
    void malformedCiphertextReturnsError() {
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("keyName", "test-key", "ciphertext", "not-a-valid-ciphertext"))
                .when()
                .post("/api/v1/internal/secrets/transit/decrypt")
                .then()
                .statusCode(400)
                .body("error", notNullValue());
    }

    @Test
    void requestWithoutAuthReturns401() {
        given()
                .contentType("application/json")
                .body(Map.of("keyName", "test-key", "plaintext", "dGVzdA=="))
                .when()
                .post("/api/v1/internal/secrets/transit/encrypt")
                .then()
                .statusCode(401);
    }
}
