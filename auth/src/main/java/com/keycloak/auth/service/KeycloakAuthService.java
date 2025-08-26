package com.keycloak.auth.service;

import com.keycloak.auth.*;
import com.keycloak.common.*;
import org.springframework.security.core.Authentication;

public interface KeycloakAuthService {
    String registerUser(RegisterRequest request);
    LoginResponse login(LoginRequest request);

    UserInfoResponse getUserInfo(Authentication authentication);
    UserInfoResponse getUserDetails(String userId);

    LoginResponse refreshToken(RefreshTokenDtO refreshTokenDtO);
    String logout(Authentication authentication);

    String updateUser(String userId, UpdateUserRequest request);
}
