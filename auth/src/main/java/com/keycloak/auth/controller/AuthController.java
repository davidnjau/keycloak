package com.keycloak.auth.controller;

import com.keycloak.auth.service.KeycloakAuthService;
import com.keycloak.auth.service.KeycloakAuthServiceImpl;
import com.keycloak.common.LoginRequest;
import com.keycloak.common.LoginResponse;
import com.keycloak.common.RegisterRequest;
import com.keycloak.common.response.ResponseWrapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller class for handling authentication-related operations.
 */
@RestController
@RequestMapping("/auth/")
@RequiredArgsConstructor
public class AuthController {

    private final KeycloakAuthService keycloakService;

    /**
     * Registers a new user in the system.
     *
     * @param request The RegisterRequest object containing user registration details.
     * @return ResponseEntity containing a ResponseWrapper with a String message indicating the result of the registration process.
     */
    @PostMapping("register")
    public ResponseEntity<ResponseWrapper<String>> register(@RequestBody RegisterRequest request) {
        String registerUser = keycloakService.registerUser(request);
        return ResponseEntity.ok(ResponseWrapper.success(registerUser));
    }

    /**
     * Authenticates a user and generates a login response.
     *
     * @param request The LoginRequest object containing user login credentials.
     * @return ResponseEntity containing a ResponseWrapper with a LoginResponse object, which includes authentication details such as tokens.
     */
    @PostMapping("login")
    public ResponseEntity<ResponseWrapper<LoginResponse>> login(@RequestBody LoginRequest request) {
        LoginResponse loginResponse = keycloakService.login(request);
        return ResponseEntity.ok(ResponseWrapper.success(loginResponse));
    }
}
