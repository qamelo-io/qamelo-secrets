package io.qamelo.secrets.domain.kv;

import java.time.Instant;

public record KvWriteResult(int version, Instant createdTime) {
}
