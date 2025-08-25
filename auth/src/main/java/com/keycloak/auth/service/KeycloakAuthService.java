package com.keycloak.auth.service;

import com.keycloak.auth.*;
import org.springframework.security.core.Authentication;

public interface KeycloakAuthService {
    ApiResponse registerUser(RegisterRequest request);
    ApiResponse login(LoginRequest request);
    ApiResponse getUserInfo(Authentication authentication);
    ApiResponse getUserDetails(String userId);
    ApiResponse refreshToken(RefreshTokenDtO refreshTokenDtO);
}
