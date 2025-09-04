package com.keycloak.products.controller;

import com.keycloak.common.response.ResponseWrapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/product/")
@RequiredArgsConstructor
public class ProductController {

    @PostMapping("create")
    public ResponseEntity<ResponseWrapper<String>> createProduct() {
        // Implement product creation logic
    }

}
