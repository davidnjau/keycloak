package com.keycloak.auth;

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

    public String getTokenUrl() {
        return serverUrl + "/realms/" + realm + "/protocol/openid-connect/token";
    }

    public String getUserInfoUrl() {
        return serverUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";
    }

    public String getAdminTokenUrl() {
        return serverUrl + "/realms/master/protocol/openid-connect/token";
    }

    public String getCreateUserUrl() {
        return serverUrl + "/admin/realms/" + realm + "/users";
    }

}
