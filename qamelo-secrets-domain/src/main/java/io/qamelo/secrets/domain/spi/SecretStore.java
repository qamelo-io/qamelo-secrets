package io.qamelo.secrets.domain.spi;

import io.qamelo.secrets.domain.kv.KvMetadata;
import io.qamelo.secrets.domain.kv.KvSecret;
import io.qamelo.secrets.domain.kv.KvWriteResult;
import io.smallrye.mutiny.Uni;

import java.util.Map;

/**
 * KV v2 secret engine — versioned key-value credential storage.
 * Paths are caller-provided (broker is pass-through).
 */
public interface SecretStore {

    Uni<KvSecret> read(String path);

    Uni<KvSecret> read(String path, int version);

    Uni<KvWriteResult> write(String path, Map<String, String> data);

    Uni<KvWriteResult> write(String path, Map<String, String> data, int cas);

    Uni<Void> delete(String path);

    Uni<KvMetadata> readMetadata(String path);
}
