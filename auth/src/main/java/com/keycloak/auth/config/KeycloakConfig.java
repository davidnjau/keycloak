
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

    /**
     * Creates and configures a Keycloak client for service account authentication.
     * This method sets up a Keycloak instance using client credentials flow,
     * which is suitable for server-to-server authentication scenarios.
     *
     * @return A configured Keycloak instance for service account authentication.
     */
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
     * Creates a Keycloak client for user authentication on demand.
     * This method sets up a Keycloak instance using the password grant type,
     * which is suitable for scenarios where you need to authenticate as a specific user.
     * 
     * Note: The caller is responsible for closing the returned Keycloak instance.
     *
     * @param username The username of the user to authenticate.
     * @param password The password of the user to authenticate.
     * @return A configured Keycloak instance for user authentication.
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

    /**
     * Closes the shared ResteasyClient when the bean is destroyed.
     * This method ensures that resources are properly released when the application shuts down.
     */
    @PreDestroy
    public void shutdown() {
        if (this.sharedClient != null) {
            this.sharedClient.close();
        }
    }

}
