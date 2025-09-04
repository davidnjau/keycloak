package com.keycloak.products.controller;

import com.keycloak.common.DBPaginatedResult;
import com.keycloak.common.DbProductCategory;
import com.keycloak.common.response.*;
import com.keycloak.products.service_impl.service.CategoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/category/")
@RequiredArgsConstructor
public class CategoryController {

    private final CategoryService categoryService;

    @PostMapping("create")
    public ResponseEntity<ResponseWrapper<String>> createCategory(
            @RequestBody DbProductCategory dbProductCategory) {

        String response = categoryService.createCategory(dbProductCategory);
        return ResponseEntity.ok(ResponseWrapper.success(response));

    }

    @GetMapping("")
    public ResponseEntity<ResponseWrapper<DBPaginatedResult>> getAllCategories(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "10") int size,
            @RequestParam(name = "sortBy", defaultValue = "name") String sortBy,
            @RequestParam(name = "order", defaultValue = "asc") String order
    ) {
        DBPaginatedResult response = categoryService.getAllCategories(
                page, size, sortBy, order
        );
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @GetMapping("{categoryId}")
    public ResponseEntity<ResponseWrapper<DbProductCategory>> getCategoryById(
            @PathVariable("categoryId") String categoryId) {

        DbProductCategory response = categoryService.getCategoryById(categoryId);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @PutMapping("{categoryId}")
    public ResponseEntity<ResponseWrapper<DbProductCategory>> updateCategory(
            @PathVariable("categoryId") String categoryId,
            @RequestBody DbProductCategory dbProductCategory) {
        DbProductCategory response = categoryService.updateCategory(dbProductCategory, categoryId);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }

    @DeleteMapping("{categoryId}")
    public ResponseEntity<ResponseWrapper<String>> deleteCategory(
            @PathVariable("categoryId") String categoryId) {
        String response = categoryService.deleteCategory(categoryId);
        return ResponseEntity.ok(ResponseWrapper.success(response));
    }



}
