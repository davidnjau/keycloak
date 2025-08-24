package com.keycloak.auth.controller;

import com.keycloak.auth.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/")
@RequiredArgsConstructor
public class AuthController {

    private final KeycloakAuthService keycloakService;

    @PostMapping("register")
    public ResponseEntity<ApiResponse> register(@RequestBody RegisterRequest request) {
        ApiResponse dbDetails = keycloakService.registerUser(request);
        return ResponseEntity.status(dbDetails.getStatusCode()).body(dbDetails);

    }

    @PostMapping("login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(keycloakService.login(request));
    }

}
