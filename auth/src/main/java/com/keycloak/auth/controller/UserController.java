package com.keycloak.auth.controller;

import com.keycloak.auth.ApiResponse;
import com.keycloak.auth.LoginRequest;
import com.keycloak.auth.RefreshTokenDtO;
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
    public ResponseEntity<ApiResponse> getCurrentUser(Authentication authentication) {

        ApiResponse apiResponse = keycloakAuthService.getUserInfo(authentication); // Ensure user info is fetched
        return ResponseEntity.status(apiResponse.getStatusCode()).body(apiResponse);
    }

    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponse> getUserById(@PathVariable("userId") String userId) {
        ApiResponse apiResponse = keycloakAuthService.getUserDetails(userId); // Ensure user info is fetched
        return ResponseEntity.status(apiResponse.getStatusCode()).body(apiResponse);
    }


    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse> refreshToken(@RequestBody RefreshTokenDtO refreshTokenDtO) {
        ApiResponse dbDetails = keycloakAuthService.refreshToken(refreshTokenDtO);
        return ResponseEntity.status(dbDetails.getStatusCode()).body(dbDetails);
    }
}