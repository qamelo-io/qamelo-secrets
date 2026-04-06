package io.qamelo.secrets.app.ssh;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
@QuarkusTestResource(VaultTestResource.class)
class SshResourceTest {

    private static String testPublicKey;

    @BeforeAll
    static void setupVault() throws Exception {
        String vaultUrl = "http://" + VaultTestResource.VAULT.getHost()
                + ":" + VaultTestResource.VAULT.getFirstMappedPort();

        // Generate a valid SSH public key for testing
        testPublicKey = generateSshPublicKey();

        try (HttpClient client = HttpClient.newHttpClient()) {
            // Configure CA for SSH signing
            HttpRequest configCa = HttpRequest.newBuilder()
                    .uri(URI.create(vaultUrl + "/v1/ssh-client-signer/config/ca"))
                    .header("X-Vault-Token", VaultTestResource.VAULT_TOKEN)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{\"generate_signing_key\":true}"))
                    .build();
            client.send(configCa, HttpResponse.BodyHandlers.ofString());

            // Create a signing role
            HttpRequest createSignRole = HttpRequest.newBuilder()
                    .uri(URI.create(vaultUrl + "/v1/ssh-client-signer/roles/test-role"))
                    .header("X-Vault-Token", VaultTestResource.VAULT_TOKEN)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "{\"key_type\":\"ca\",\"allow_user_certificates\":true,"
                                    + "\"allowed_users\":\"*\",\"default_extensions\":{\"permit-pty\":\"\"},"
                                    + "\"ttl\":\"30m\"}"))
                    .build();
            client.send(createSignRole, HttpResponse.BodyHandlers.ofString());

            // Create an OTP role
            HttpRequest createOtpRole = HttpRequest.newBuilder()
                    .uri(URI.create(vaultUrl + "/v1/ssh-client-signer/roles/otp-role"))
                    .header("X-Vault-Token", VaultTestResource.VAULT_TOKEN)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "{\"key_type\":\"otp\",\"default_user\":\"ubuntu\","
                                    + "\"cidr_list\":\"0.0.0.0/0\"}"))
                    .build();
            client.send(createOtpRole, HttpResponse.BodyHandlers.ofString());
        }
    }

    @Test
    void signPublicKey() {
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("roleName", "test-role", "publicKey", testPublicKey))
                .when()
                .post("/api/v1/internal/secrets/ssh/sign")
                .then()
                .statusCode(200)
                .body("signedKey", notNullValue());
    }

    @Test
    void generateOtp() {
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("roleName", "otp-role", "ip", "10.0.0.1"))
                .when()
                .post("/api/v1/internal/secrets/ssh/otp")
                .then()
                .statusCode(200)
                .body("key", notNullValue())
                .body("username", notNullValue());
    }

    @Test
    void signWithNonexistentRoleReturnsError() {
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("roleName", "nonexistent-role", "publicKey", testPublicKey))
                .when()
                .post("/api/v1/internal/secrets/ssh/sign")
                .then()
                .statusCode(400)
                .body("error", notNullValue());
    }

    @Test
    void requestWithoutAuthReturns401() {
        given()
                .contentType("application/json")
                .body(Map.of("roleName", "test-role", "publicKey", testPublicKey))
                .when()
                .post("/api/v1/internal/secrets/ssh/sign")
                .then()
                .statusCode(401);
    }

    /**
     * Generate an OpenSSH-format RSA public key for testing.
     */
    private static String generateSshPublicKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // Build SSH RSA public key wire format
        byte[] typeBytes = "ssh-rsa".getBytes();
        byte[] exponentBytes = publicKey.getPublicExponent().toByteArray();
        byte[] modulusBytes = publicKey.getModulus().toByteArray();

        int totalLength = 4 + typeBytes.length + 4 + exponentBytes.length + 4 + modulusBytes.length;
        byte[] keyBlob = new byte[totalLength];
        int offset = 0;

        offset = writeBytes(keyBlob, offset, typeBytes);
        offset = writeBytes(keyBlob, offset, exponentBytes);
        writeBytes(keyBlob, offset, modulusBytes);

        return "ssh-rsa " + Base64.getEncoder().encodeToString(keyBlob) + " test@test";
    }

    private static int writeBytes(byte[] dest, int offset, byte[] src) {
        dest[offset] = (byte) ((src.length >> 24) & 0xFF);
        dest[offset + 1] = (byte) ((src.length >> 16) & 0xFF);
        dest[offset + 2] = (byte) ((src.length >> 8) & 0xFF);
        dest[offset + 3] = (byte) (src.length & 0xFF);
        System.arraycopy(src, 0, dest, offset + 4, src.length);
        return offset + 4 + src.length;
    }
}
