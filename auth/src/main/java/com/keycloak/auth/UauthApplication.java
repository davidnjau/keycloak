package com.keycloak.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication(scanBasePackages = {"com.keycloak.auth", "com.keycloak.common"} )
@EnableCaching
public class UauthApplication {
    public static void main(String[] args) {
        SpringApplication.run(UauthApplication.class, args);
    }
}
