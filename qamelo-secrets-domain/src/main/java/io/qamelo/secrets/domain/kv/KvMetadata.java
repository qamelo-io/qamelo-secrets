package io.qamelo.secrets.domain.kv;

import java.time.Instant;
import java.util.Map;

public record KvMetadata(
        int currentVersion,
        Instant createdTime,
        Instant updatedTime,
        Map<Integer, KvVersionInfo> versions) {
}
