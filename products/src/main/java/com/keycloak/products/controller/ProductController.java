package com.keycloak.products.controller;

import com.keycloak.common.DBPaginatedResult;
import com.keycloak.common.DbCategories;
import com.keycloak.common.DbProduct;
import com.keycloak.common.response.ResponseWrapper;
import com.keycloak.products.service_impl.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/product/")
@RequiredArgsConstructor
public class ProductController {

    private final ProductService productService;

    @PostMapping("create")
    public ResponseEntity<ResponseWrapper<DbProduct>> createProduct(
            @RequestBody DbProduct dbProduct) {

        DbProduct response = productService.createProduct(dbProduct);
        return ResponseEntity.ok(ResponseWrapper.success(response));

    }

    @GetMapping("")
    public ResponseEntity<ResponseWrapper<DBPaginatedResult>> getAllCategories(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "10") int size,
            @RequestParam(name = "sortBy", defaultValue = "name") String sortBy,
            @RequestParam(name = "order", defaultValue = "asc") String order,
            @RequestParam(name = "isActive", defaultValue = "true") Boolean isActive
    ) {
        DBPaginatedResult response = productService.getProducts(
                page, size, sortBy, order,isActive
        );
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @GetMapping("{productId}")
    public ResponseEntity<ResponseWrapper<DbProduct>> getProductById(
            @PathVariable("productId") String productId) {

        DbProduct response = productService.getProductById(productId);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @PutMapping("update/{productId}")
    public ResponseEntity<ResponseWrapper<DbProduct>> updateProduct(
            @PathVariable("productId") String productId,
            @RequestBody DbProduct dbProduct) {
        DbProduct response = productService.updateProduct(dbProduct, productId);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @DeleteMapping("{productId}")
    public ResponseEntity<ResponseWrapper<String>> deleteProduct(
            @PathVariable("productId") String productId) {
        String response = productService.deleteProduct(productId);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @PutMapping("add-category/{productId}")
    public ResponseEntity<ResponseWrapper<String>> addProductToCategory(
            @PathVariable("productId") String productId,
            @RequestBody DbCategories dbCategories) {
        String response = productService.addProductToCategory(productId, dbCategories);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @PutMapping("remove-category/{productId}")
    public ResponseEntity<ResponseWrapper<String>> removeProductFromCategory(
            @PathVariable("productId") String productId,
            @RequestBody DbCategories dbCategories) {
        String response = productService.removeProductFromCategory(productId, dbCategories);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

}
