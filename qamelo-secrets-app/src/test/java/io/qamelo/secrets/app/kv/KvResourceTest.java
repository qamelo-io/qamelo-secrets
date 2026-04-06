package io.qamelo.secrets.app.kv;

import io.qamelo.secrets.app.VaultTestResource;
import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

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
    void readSpecificVersion() {
        String path = "connections/version-read/credentials";

        // Write v1
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("password", "original")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(1));

        // Write v2
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("password", "updated")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(2));

        // Read v1 explicitly — should return original value
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path + "?version=1")
                .then()
                .statusCode(200)
                .body("data.password", equalTo("original"))
                .body("version", equalTo(1));

        // Read v2 explicitly
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path + "?version=2")
                .then()
                .statusCode(200)
                .body("data.password", equalTo("updated"))
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
    void readMetadata() {
        String path = "connections/metadata-test/credentials";

        // Write v1
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("key", "value1")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(1));

        // Write v2
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("key", "value2")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(2));

        // Read metadata
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path + "/metadata")
                .then()
                .statusCode(200)
                .body("currentVersion", equalTo(2))
                .body("createdTime", notNullValue())
                .body("updatedTime", notNullValue())
                .body("versions.1.version", equalTo(1))
                .body("versions.1.createdTime", notNullValue())
                .body("versions.2.version", equalTo(2))
                .body("versions.2.createdTime", notNullValue());
    }

    @Test
    void softDeleteThenRead() {
        String path = "connections/soft-delete-test/credentials";

        // Write
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("key", "to-delete")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(1));

        // Delete (soft)
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .delete("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(204);

        // Read after delete — should be 404
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(404)
                .body("error", equalTo("SECRET_NOT_FOUND"));

        // Metadata should still exist and show deletion
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path + "/metadata")
                .then()
                .statusCode(200)
                .body("currentVersion", equalTo(1))
                .body("versions.1.deletionTime", notNullValue());
    }

    @Test
    void casWriteSuccess() {
        String path = "connections/cas-success/credentials";

        // Write v1
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("key", "initial")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(1));

        // CAS write with cas=1 (current version) — should succeed
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("key", "cas-updated")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path + "?cas=1")
                .then()
                .statusCode(200)
                .body("version", equalTo(2));

        // Verify the new value
        given()
                .header("Authorization", "Bearer test-secret")
                .when()
                .get("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("data.key", equalTo("cas-updated"))
                .body("version", equalTo(2));
    }

    @Test
    void casWriteConflict() {
        String path = "connections/cas-conflict/credentials";

        // Write v1
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("key", "initial")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path)
                .then()
                .statusCode(200)
                .body("version", equalTo(1));

        // CAS write with cas=0 (wrong version) — should return 409
        given()
                .header("Authorization", "Bearer test-secret")
                .contentType("application/json")
                .body(Map.of("data", Map.of("key", "conflict-attempt")))
                .when()
                .put("/api/v1/internal/secrets/kv/" + path + "?cas=0")
                .then()
                .statusCode(409)
                .body("error", equalTo("INVALID_REQUEST"))
                .body("message", containsString("CAS conflict"));
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
