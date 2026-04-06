package io.qamelo.secrets.infra.vault;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

import java.util.Optional;

@ConfigMapping(prefix = "qamelo.vault")
public interface VaultConfig {

    @WithDefault("http://vault.qamelo-system:8200")
    String url();

    Auth auth();

    Mount mount();

    interface Auth {

        @WithDefault("kubernetes")
        String method();

        Kubernetes kubernetes();

        Optional<String> token();

        interface Kubernetes {

            @WithDefault("qamelo-secrets")
            String role();
        }
    }

    interface Mount {

        @WithDefault("kv")
        String kv();

        @WithDefault("pki")
        String pki();

        @WithDefault("transit")
        String transit();

        @WithDefault("ssh")
        String ssh();

        @WithDefault("database")
        String database();
    }
}
