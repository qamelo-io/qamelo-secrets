package io.qamelo.secrets.app.database;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;

@QuarkusTest
@QuarkusTestResource(VaultTestResource.class)
@QuarkusTestResource(DatabaseTestResource.class)
class DatabaseResourceTest {

    @Test
    void generateCredentials() {
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .when()
                .post("/api/v1/internal/secrets/database/creds/test-role")
                .then()
                .statusCode(200)
                .body("username", notNullValue())
                .body("password", notNullValue())
                .body("leaseId", notNullValue())
                .body("leaseDuration", greaterThan(0));
    }

    @Test
    void generatedCredentialsConnectToDatabase() throws Exception {
        var response = given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .when()
                .post("/api/v1/internal/secrets/database/creds/test-role")
                .then()
                .statusCode(200)
                .extract()
                .response();

        String username = response.jsonPath().getString("username");
        String password = response.jsonPath().getString("password");

        String jdbcUrl = "jdbc:postgresql://" + DatabaseTestResource.POSTGRES.getHost()
                + ":" + DatabaseTestResource.POSTGRES.getFirstMappedPort()
                + "/test";

        try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password)) {
            assertThat(conn.isValid(5)).isTrue();
        }
    }

    @Test
    void renewLease() {
        // Generate credentials first to get a lease
        var response = given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .when()
                .post("/api/v1/internal/secrets/database/creds/test-role")
                .then()
                .statusCode(200)
                .extract()
                .response();

        String leaseId = response.jsonPath().getString("leaseId");

        // Renew the lease
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("leaseId", leaseId, "increment", 3600))
                .when()
                .post("/api/v1/internal/secrets/database/leases/renew")
                .then()
                .statusCode(200)
                .body("leaseId", equalTo(leaseId))
                .body("leaseDuration", greaterThan(0))
                .body("renewable", equalTo(true));
    }

    @Test
    void revokeLease() throws Exception {
        // Generate credentials
        var response = given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .when()
                .post("/api/v1/internal/secrets/database/creds/test-role")
                .then()
                .statusCode(200)
                .extract()
                .response();

        String leaseId = response.jsonPath().getString("leaseId");
        String username = response.jsonPath().getString("username");
        String password = response.jsonPath().getString("password");

        String jdbcUrl = "jdbc:postgresql://" + DatabaseTestResource.POSTGRES.getHost()
                + ":" + DatabaseTestResource.POSTGRES.getFirstMappedPort()
                + "/test";

        // Verify credentials work before revocation
        try (Connection conn = DriverManager.getConnection(jdbcUrl, username, password)) {
            assertThat(conn.isValid(5)).isTrue();
        }

        // Revoke the lease
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("leaseId", leaseId))
                .when()
                .post("/api/v1/internal/secrets/database/leases/revoke")
                .then()
                .statusCode(204);

        // Credentials should no longer work after revocation
        try {
            Connection conn = DriverManager.getConnection(jdbcUrl, username, password);
            conn.close();
            throw new AssertionError("Expected JDBC connection to fail after lease revocation");
        } catch (java.sql.SQLException expected) {
            // Expected: credentials have been revoked
        }
    }

    @Test
    void nonexistentRoleReturnsError() {
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .when()
                .post("/api/v1/internal/secrets/database/creds/nonexistent")
                .then()
                .statusCode(anyOf(equalTo(400), equalTo(502)));
    }

    @Test
    void nonexistentLeaseReturnsLeaseExpired() {
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("leaseId", "database/creds/test-role/nonexistent-lease-id", "increment", 3600))
                .when()
                .post("/api/v1/internal/secrets/database/leases/renew")
                .then()
                .statusCode(410)
                .body("error", equalTo("LEASE_EXPIRED"));
    }

    @Test
    void requestWithoutAuthReturns401() {
        given()
                .contentType("application/json")
                .when()
                .post("/api/v1/internal/secrets/database/creds/test-role")
                .then()
                .statusCode(401);
    }
}
