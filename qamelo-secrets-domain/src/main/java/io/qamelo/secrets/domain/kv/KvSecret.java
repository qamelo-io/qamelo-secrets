package io.qamelo.secrets.domain.kv;

import java.time.Instant;
import java.util.Map;

public record KvSecret(Map<String, String> data, int version, Instant createdTime) {
}
