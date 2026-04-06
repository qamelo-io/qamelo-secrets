package io.qamelo.secrets.domain.kv;

import java.time.Instant;

public record KvVersionInfo(int version, Instant createdTime, Instant deletionTime, boolean destroyed) {
}
