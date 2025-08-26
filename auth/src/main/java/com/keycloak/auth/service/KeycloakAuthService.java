package com.keycloak.auth.service;

import com.keycloak.auth.*;
import org.springframework.security.core.Authentication;

public interface KeycloakAuthService {
    String registerUser(RegisterRequest request);
    LoginResponse login(LoginRequest request);

    UserInfoResponse getUserInfo(Authentication authentication);
    ApiResponse getUserDetails(String userId);
    ApiResponse refreshToken(RefreshTokenDtO refreshTokenDtO);
    ApiResponse logout(Authentication authentication);
    ApiResponse updateUser(String userId, UpdateUserRequest request);
}
