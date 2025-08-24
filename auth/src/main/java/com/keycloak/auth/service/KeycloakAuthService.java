package com.keycloak.auth.service;

import com.keycloak.auth.*;
import org.springframework.security.core.Authentication;

public interface KeycloakAuthService {
    public ApiResponse registerUser(RegisterRequest request);
    public LoginResponse login(LoginRequest request);
    UserInfoResponse getUserInfo(Authentication authentication);
}
