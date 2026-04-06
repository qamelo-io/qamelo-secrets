package io.qamelo.secrets.app.health;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

@QuarkusTest
@QuarkusTestResource(VaultTestResource.class)
class HealthCheckTest {

    @Test
    void readinessUpWhenVaultReachable() {
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void livenessAlwaysUp() {
        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void detailedHealthEndpointShowsVaultConnected() {
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/health")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("vault", equalTo("CONNECTED"))
                .body("auth", equalTo("TOKEN"));
    }
}
