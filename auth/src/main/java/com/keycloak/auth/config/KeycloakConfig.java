package com.keycloak.auth.config;

import lombok.RequiredArgsConstructor;
import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PreDestroy;

@Configuration
@RequiredArgsConstructor
public class KeycloakConfig {

    private final KeycloakProperties keycloakProperties;
    private ResteasyClient sharedClient;

    @Bean
    public Keycloak serviceAccountKeycloakClient() {

        return KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getServerUrl())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .realm(keycloakProperties.getRealm())
                .clientId(keycloakProperties.getClientId())
                .clientSecret(keycloakProperties.getClientSecret())
                .resteasyClient(new ResteasyClientBuilder()
                        .connectionPoolSize(10)
                        .build())
                .build();
    }

    /**
     * Non-bean factory method for on-demand user client (username/password).
     * Note: caller is responsible for closing the returned Keycloak instance.
     */
    public Keycloak userKeycloakClient(String username, String password) {


        // Password grant for obtaining tokens for a user
        return KeycloakBuilder.builder()
                .serverUrl(keycloakProperties.getServerUrl())
                .realm(keycloakProperties.getRealm())
                .username(username)
                .password(password)
                .clientId(keycloakProperties.getClientId())
                .clientSecret(keycloakProperties.getClientSecret())
                .grantType(OAuth2Constants.PASSWORD)
                .resteasyClient(new ResteasyClientBuilder()
                        .connectionPoolSize(10)
                        .build())
                .build();
    }

    @PreDestroy
    public void shutdown() {
        if (this.sharedClient != null) {
            this.sharedClient.close();
        }
    }

}
