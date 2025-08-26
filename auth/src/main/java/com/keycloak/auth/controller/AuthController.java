package com.keycloak.auth.controller;

import com.keycloak.auth.*;
import com.keycloak.auth.service.KeycloakAuthServiceImpl;
import com.keycloak.common.exception.BadRequestException;
import com.keycloak.common.response.ResponseWrapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth/")
@RequiredArgsConstructor
public class AuthController {

    private final KeycloakAuthServiceImpl keycloakService;

    @PostMapping("register")
    public ResponseEntity<ResponseWrapper<String>> register(@RequestBody RegisterRequest request) {
        String registerUser = keycloakService.registerUser(request);
        return ResponseEntity.ok(ResponseWrapper.success(registerUser));

    }

    @PostMapping("login")
    public ResponseEntity<ResponseWrapper<LoginResponse>> login(@RequestBody LoginRequest request) {
        LoginResponse loginResponse = keycloakService.login(request);
        return ResponseEntity.ok(ResponseWrapper.success(loginResponse));
    }

}
