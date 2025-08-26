
package com.keycloak.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "keycloak")
public class KeycloakProperties {

    private String serverUrl;
    private String realm;
    private String clientId;
    private String clientSecret;
    private String adminUsername;
    private String adminPassword;
    private String principleAttribute;
    private String defaultRole;

    /**
     * Constructs the URL for obtaining an access token from Keycloak.
     *
     * @return A String representing the complete URL for the token endpoint.
     */
    public String getTokenUrl() {
        return serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";
    }

    /**
     * Constructs the URL for retrieving user information from Keycloak.
     *
     * @return A String representing the complete URL for the user info endpoint.
     */
    public String getUserInfoUrl() {
        return serverUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";
    }

    /**
     * Constructs the URL for obtaining an admin access token from Keycloak.
     *
     * @return A String representing the complete URL for the admin token endpoint.
     */
    public String getAdminTokenUrl() {
        return serverUrl + "/realms/master/protocol/openid-connect/token";
    }

    /**
     * Constructs the URL for creating a new user in Keycloak.
     *
     * @return A String representing the complete URL for the user creation endpoint.
     */
    public String getCreateUserUrl() {
        return serverUrl + "/admin/realms/" + realm + "/users";
    }
}
