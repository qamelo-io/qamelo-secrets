package io.qamelo.secrets.app.pki;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

@QuarkusTest
@QuarkusTestResource(VaultTestResource.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PkiResourceTest {

    private static final String AUTH_HEADER = "Bearer test-secret";

    @BeforeAll
    static void setupPkiEngine() throws Exception {
        String vaultUrl = "http://" + VaultTestResource.VAULT.getHost()
                + ":" + VaultTestResource.VAULT.getFirstMappedPort();
        String token = VaultTestResource.VAULT_TOKEN;

        HttpClient client = HttpClient.newHttpClient();

        // 1. Generate internal root CA
        HttpRequest generateRoot = HttpRequest.newBuilder()
                .uri(URI.create(vaultUrl + "/v1/pki/root/generate/internal"))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"common_name\": \"Test Root CA\", \"ttl\": \"87600h\"}"))
                .build();
        HttpResponse<String> rootResp = client.send(generateRoot, HttpResponse.BodyHandlers.ofString());
        if (rootResp.statusCode() >= 300) {
            throw new RuntimeException("Failed to generate root CA: " + rootResp.statusCode() + " " + rootResp.body());
        }

        // 2. Configure URLs
        HttpRequest configUrls = HttpRequest.newBuilder()
                .uri(URI.create(vaultUrl + "/v1/pki/config/urls"))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"issuing_certificates\": \"" + vaultUrl + "/v1/pki/ca\","
                                + "\"crl_distribution_points\": \"" + vaultUrl + "/v1/pki/crl\"}"))
                .build();
        HttpResponse<String> urlsResp = client.send(configUrls, HttpResponse.BodyHandlers.ofString());
        if (urlsResp.statusCode() >= 300) {
            throw new RuntimeException("Failed to configure URLs: " + urlsResp.statusCode() + " " + urlsResp.body());
        }

        // 3. Create role for testing
        HttpRequest createRole = HttpRequest.newBuilder()
                .uri(URI.create(vaultUrl + "/v1/pki/roles/test-role"))
                .header("X-Vault-Token", token)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"allowed_domains\": [\"example.com\"],"
                                + "\"allow_subdomains\": true,"
                                + "\"max_ttl\": \"72h\"}"))
                .build();
        HttpResponse<String> roleResp = client.send(createRole, HttpResponse.BodyHandlers.ofString());
        if (roleResp.statusCode() >= 300) {
            throw new RuntimeException("Failed to create role: " + roleResp.statusCode() + " " + roleResp.body());
        }
    }

    @Test
    @Order(1)
    void issueCertificate() {
        given()
                .header("Authorization", AUTH_HEADER)
                .contentType("application/json")
                .body(Map.of(
                        "roleName", "test-role",
                        "commonName", "app.example.com",
                        "ttl", "24h"
                ))
                .when()
                .post("/api/v1/internal/secrets/pki/issue")
                .then()
                .statusCode(200)
                .body("serialNumber", notNullValue())
                .body("certificatePem", startsWith("-----BEGIN CERTIFICATE-----"))
                .body("privateKeyPem", notNullValue())
                .body("issuingCaPem", startsWith("-----BEGIN CERTIFICATE-----"))
                .body("expiration", notNullValue());
    }

    @Test
    @Order(2)
    void readCertificate() {
        // First issue a certificate
        String serial = given()
                .header("Authorization", AUTH_HEADER)
                .contentType("application/json")
                .body(Map.of(
                        "roleName", "test-role",
                        "commonName", "read-test.example.com",
                        "ttl", "24h"
                ))
                .when()
                .post("/api/v1/internal/secrets/pki/issue")
                .then()
                .statusCode(200)
                .extract().path("serialNumber");

        // Then read it back
        given()
                .header("Authorization", AUTH_HEADER)
                .when()
                .get("/api/v1/internal/secrets/pki/cert/" + serial)
                .then()
                .statusCode(200)
                .body("serialNumber", equalTo(serial))
                .body("certificatePem", startsWith("-----BEGIN CERTIFICATE-----"))
                .body("revoked", equalTo(false));
    }

    @Test
    @Order(3)
    void revokeCertificate() {
        // Issue a certificate
        String serial = given()
                .header("Authorization", AUTH_HEADER)
                .contentType("application/json")
                .body(Map.of(
                        "roleName", "test-role",
                        "commonName", "revoke-test.example.com",
                        "ttl", "24h"
                ))
                .when()
                .post("/api/v1/internal/secrets/pki/issue")
                .then()
                .statusCode(200)
                .extract().path("serialNumber");

        // Revoke it
        given()
                .header("Authorization", AUTH_HEADER)
                .contentType("application/json")
                .body(Map.of("serialNumber", serial))
                .when()
                .post("/api/v1/internal/secrets/pki/revoke")
                .then()
                .statusCode(204);
    }

    @Test
    @Order(4)
    void getCaCertificate() {
        given()
                .header("Authorization", AUTH_HEADER)
                .when()
                .get("/api/v1/internal/secrets/pki/ca")
                .then()
                .statusCode(200)
                .body("certificatePem", startsWith("-----BEGIN CERTIFICATE-----"));
    }

    @Test
    @Order(5)
    void listExpiringCertificates() {
        // Issue a certificate with short TTL
        given()
                .header("Authorization", AUTH_HEADER)
                .contentType("application/json")
                .body(Map.of(
                        "roleName", "test-role",
                        "commonName", "expiring-test.example.com",
                        "ttl", "1h"
                ))
                .when()
                .post("/api/v1/internal/secrets/pki/issue")
                .then()
                .statusCode(200);

        // List certificates expiring within 48 hours — should include the one we just issued
        given()
                .header("Authorization", AUTH_HEADER)
                .when()
                .get("/api/v1/internal/secrets/pki/certs/expiring?within=48h")
                .then()
                .statusCode(200)
                .body("$.size()", greaterThan(0));
    }

    @Test
    @Order(6)
    void nonexistentSerialReturns404() {
        given()
                .header("Authorization", AUTH_HEADER)
                .when()
                .get("/api/v1/internal/secrets/pki/cert/00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00")
                .then()
                .statusCode(404)
                .body("error", equalTo("SECRET_NOT_FOUND"));
    }

    @Test
    @Order(7)
    void requestWithoutAuthReturns401() {
        given()
                .when()
                .get("/api/v1/internal/secrets/pki/ca")
                .then()
                .statusCode(401);
    }
}
