package com.keycloak.products.service_impl.service;

import com.keycloak.common.DbProductCategory;

import java.util.List;

public interface CategoryService {

    String createCategory(DbProductCategory dbProductCategory);
    List<DbProductCategory> getAllCategories(int page, int size, String sortBy, String order);
    DbProductCategory getCategoryById(String id);
    DbProductCategory updateCategory(DbProductCategory dbProductCategory, String categoryId);
    String deleteCategory(String id);


}
