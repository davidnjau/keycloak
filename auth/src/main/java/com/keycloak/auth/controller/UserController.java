package com.keycloak.auth.controller;

import com.keycloak.auth.*;
import com.keycloak.auth.service.KeycloakAuthService;
import com.keycloak.common.*;
import com.keycloak.common.response.ResponseWrapper;
import lombok.RequiredArgsConstructor;
import org.jboss.resteasy.spi.NotFoundException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<ResponseWrapper<UserInfoResponse>> getCurrentUser(Authentication authentication) {

        UserInfoResponse response = keycloakAuthService.getUserInfo(authentication); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<ResponseWrapper<UserInfoResponse>> getUserById(@PathVariable("userId") String userId) {
        UserInfoResponse response = keycloakAuthService.getUserDetails(userId); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
    @PostMapping("/refresh-token")
    public ResponseEntity<ResponseWrapper<LoginResponse>> refreshToken(@RequestBody RefreshTokenDtO refreshTokenDtO) {
        LoginResponse response = keycloakAuthService.refreshToken(refreshTokenDtO);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
    @GetMapping("/logout")
    public ResponseEntity<ResponseWrapper<String>> logout(Authentication authentication) {
        String response = keycloakAuthService.logout(authentication); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
    @PutMapping("/update-user/{userId}")
    public ResponseEntity<ResponseWrapper<String>> updateUser(@PathVariable("userId") String userId, @RequestBody UpdateUserRequest request) {
        String response = keycloakAuthService.updateUser(userId, request); // Ensure user info is fetched
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }
}