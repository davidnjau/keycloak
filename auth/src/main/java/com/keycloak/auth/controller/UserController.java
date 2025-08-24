package com.keycloak.auth.controller;

import com.keycloak.auth.UserInfoResponse;
import com.keycloak.auth.service.KeycloakAuthService;
import lombok.RequiredArgsConstructor;
import org.jboss.resteasy.spi.NotFoundException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final Keycloak keycloak; // Admin client bean
    private final KeycloakAuthService keycloakAuthService;

    /**
     * Get user info from current token
     */
    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> getCurrentUser(Authentication authentication) {

        UserInfoResponse userInfoResponse = keycloakAuthService.getUserInfo(authentication); // Ensure user info is fetched
        return ResponseEntity.ok(userInfoResponse);
    }

    @GetMapping("/{userId}")
    public ResponseEntity<UserInfoResponse> getUserById(@PathVariable String userId) {
        UserInfoResponse userInfoResponse = keycloakAuthService.getUserDetails(userId); // Ensure user info is fetched
        return ResponseEntity.ok(userInfoResponse);
    }
}