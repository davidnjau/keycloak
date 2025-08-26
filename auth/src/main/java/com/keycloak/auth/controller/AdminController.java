package com.keycloak.auth;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasRole('admin')") // Checks for ROLE_admin
    public String adminDashboard() {
        return "Welcome Admin!";
    }

    @GetMapping("/reports")
    @PreAuthorize("hasAnyRole('admin', 'manager')")
    public String reports() {
        return "Manager/Admin Reports Access";
    }
}
