package io.qamelo.secrets.app.kv;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@QuarkusTest
@QuarkusTestResource(VaultTestResource.class)
class KvResourceTest {

    @Test
    void writeAndReadSecret() {
        String path = "connections/test-conn/credentials";

        // Write
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("username", "admin", "password", "s3cret")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(1));

        // Read back
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("data.username", equalTo("admin"))
                .body("data.password", equalTo("s3cret"))
                .body("version", equalTo(1));
    }

    @Test
    void writeAgainIncrementsVersion() {
        String path = "connections/versioned/credentials";

        // Write v1
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("password", "first")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(1));

        // Write v2
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("password", "second")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(2));

        // Read latest — should be v2
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("data.password", equalTo("second"))
                .body("version", equalTo(2));
    }

    @Test
    void readNonexistentReturns404() {
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/does/not/exist")
                .then()
                .statusCode(404)
                .body("error", equalTo("SECRET_NOT_FOUND"));
    }

    @Test
    void requestWithoutAuthReturns401() {
        given()
                .when()
                .get("/api/v1/internal/secrets/kv/any/path")
                .then()
                .statusCode(401);
    }
}
