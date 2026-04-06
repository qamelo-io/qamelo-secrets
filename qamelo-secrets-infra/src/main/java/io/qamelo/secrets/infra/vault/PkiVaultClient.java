package io.qamelo.secrets.infra.vault;

import io.qamelo.secrets.domain.error.SecretsErrorCode;
import io.qamelo.secrets.domain.error.SecretsException;
import io.qamelo.secrets.domain.pki.CaCertificateResponse;
import io.qamelo.secrets.domain.pki.CertificateInfo;
import io.qamelo.secrets.domain.pki.CertificateIssueRequest;
import io.qamelo.secrets.domain.pki.IssuedCertificate;
import io.qamelo.secrets.domain.spi.CertificateStore;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ApplicationScoped
public class PkiVaultClient implements CertificateStore {

    private static final Logger LOG = Logger.getLogger(PkiVaultClient.class);
    private static final Pattern WITHIN_PATTERN = Pattern.compile("^(\\d+)([dhms])$");

    @Inject
    VaultHttpClient vault;

    @Inject
    VaultConfig config;

    @Override
    public Uni<IssuedCertificate> issue(CertificateIssueRequest request) {
        String path = config.mount().pki() + "/issue/" + request.roleName();

        JsonObject body = new JsonObject()
                .put("common_name", request.commonName());

        if (request.altNames() != null && !request.altNames().isEmpty()) {
            body.put("alt_names", String.join(",", request.altNames()));
        }
        if (request.ipSans() != null && !request.ipSans().isEmpty()) {
            body.put("ip_sans", String.join(",", request.ipSans()));
        }
        if (request.ttl() != null && !request.ttl().isEmpty()) {
            body.put("ttl", request.ttl());
        }

        return vault.post(path, body).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), "issue/" + request.roleName());

            JsonObject json = new JsonObject(resp.bodyAsString());
            JsonObject data = json.getJsonObject("data");

            String serialNumber = data.getString("serial_number");
            String certificate = data.getString("certificate");
            String privateKey = data.getString("private_key");
            String issuingCa = data.getString("issuing_ca");

            String caChain = null;
            JsonArray caChainArray = data.getJsonArray("ca_chain");
            if (caChainArray != null && !caChainArray.isEmpty()) {
                caChain = String.join("\n", caChainArray.stream()
                        .map(Object::toString)
                        .toList());
            }

            long expirationEpoch = data.getLong("expiration", 0L);
            Instant expiration = Instant.ofEpochSecond(expirationEpoch);

            return new IssuedCertificate(serialNumber, certificate, privateKey, issuingCa, caChain, expiration);
        });
    }

    @Override
    public Uni<CertificateInfo> readCertificate(String serialNumber) {
        String path = config.mount().pki() + "/cert/" + serialNumber;

        return vault.get(path).map(resp -> {
            if (resp.statusCode() == 404) {
                throw new SecretsException(SecretsErrorCode.SECRET_NOT_FOUND,
                        "Certificate not found: " + serialNumber);
            }
            checkVaultError(resp.statusCode(), resp.bodyAsString(), "cert/" + serialNumber);

            JsonObject json = new JsonObject(resp.bodyAsString());
            JsonObject data = json.getJsonObject("data");

            String certificate = data.getString("certificate");
            long revocationTime = data.getLong("revocation_time", 0L);
            boolean revoked = revocationTime > 0;

            // Parse the certificate to extract notAfter
            Instant notAfter = extractNotAfterFromPem(certificate);

            return new CertificateInfo(serialNumber, certificate, notAfter, revoked);
        });
    }

    @Override
    public Uni<Void> revoke(String serialNumber) {
        String path = config.mount().pki() + "/revoke";
        JsonObject body = new JsonObject().put("serial_number", serialNumber);

        return vault.post(path, body).map(resp -> {
            checkVaultError(resp.statusCode(), resp.bodyAsString(), "revoke/" + serialNumber);
            return null;
        });
    }

    @Override
    public Uni<CaCertificateResponse> getCaCertificate() {
        String path = config.mount().pki() + "/ca/pem";

        return vault.get(path).map(resp -> {
            // The /ca/pem endpoint returns raw PEM text with 200
            // If 404, the CA has not been configured
            if (resp.statusCode() == 404) {
                throw new SecretsException(SecretsErrorCode.SECRET_NOT_FOUND, "CA certificate not found");
            }
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                checkVaultError(resp.statusCode(), resp.bodyAsString(), "ca/pem");
            }

            String pem = resp.bodyAsString();
            return new CaCertificateResponse(pem != null ? pem.trim() : null);
        });
    }

    @Override
    public Uni<List<CertificateInfo>> listExpiring(String within) {
        Duration window = parseWithin(within);
        Instant cutoff = Instant.now().plus(window);

        String path = config.mount().pki() + "/certs";

        return vault.list(path).chain(resp -> {
            if (resp.statusCode() == 404) {
                return Uni.createFrom().item(List.of());
            }
            checkVaultError(resp.statusCode(), resp.bodyAsString(), "certs");

            JsonObject json = new JsonObject(resp.bodyAsString());
            JsonObject data = json.getJsonObject("data");

            if (data == null || data.getJsonArray("keys") == null) {
                return Uni.createFrom().item(List.of());
            }

            JsonArray keys = data.getJsonArray("keys");
            List<String> serials = keys.stream()
                    .map(Object::toString)
                    .toList();

            return Multi.createFrom().iterable(serials)
                    .onItem().transformToUniAndConcatenate(this::readCertificate)
                    .filter(cert -> !cert.revoked() && cert.notAfter() != null && cert.notAfter().isBefore(cutoff))
                    .collect().asList();
        });
    }

    private Duration parseWithin(String within) {
        if (within == null || within.isEmpty()) {
            return Duration.ofDays(30);
        }
        Matcher matcher = WITHIN_PATTERN.matcher(within);
        if (!matcher.matches()) {
            throw new SecretsException(SecretsErrorCode.INVALID_REQUEST,
                    "Invalid 'within' format: " + within + ". Expected format like 30d, 24h, 60m, 3600s");
        }
        long value = Long.parseLong(matcher.group(1));
        String unit = matcher.group(2);
        return switch (unit) {
            case "d" -> Duration.ofDays(value);
            case "h" -> Duration.ofHours(value);
            case "m" -> Duration.ofMinutes(value);
            case "s" -> Duration.ofSeconds(value);
            default -> Duration.ofDays(30);
        };
    }

    private Instant extractNotAfterFromPem(String pem) {
        // Parse the X.509 certificate to get the notAfter date
        if (pem == null || pem.isEmpty()) {
            return null;
        }
        try {
            java.security.cert.CertificateFactory factory = java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) factory.generateCertificate(
                    new java.io.ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            return cert.getNotAfter().toInstant();
        } catch (Exception e) {
            LOG.warnf("Failed to parse certificate for notAfter: %s", e.getMessage());
            return null;
        }
    }

    private void checkVaultError(int statusCode, String body, String context) {
        if (statusCode >= 200 && statusCode < 300) {
            return;
        }
        SecretsErrorCode code = switch (statusCode) {
            case 403 -> SecretsErrorCode.ACCESS_DENIED;
            case 404 -> SecretsErrorCode.SECRET_NOT_FOUND;
            case 429 -> SecretsErrorCode.RATE_LIMITED;
            case 503 -> SecretsErrorCode.VAULT_UNAVAILABLE;
            default -> SecretsErrorCode.UPSTREAM_ERROR;
        };
        LOG.warnf("Vault PKI error on %s: %d %s", context, statusCode, body);
        throw new SecretsException(code, "Vault error at PKI " + context + ": " + statusCode);
    }
}
