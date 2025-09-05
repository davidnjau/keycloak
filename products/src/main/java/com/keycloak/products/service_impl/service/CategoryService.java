package com.keycloak.products.service_impl.service;

import com.keycloak.common.DBPaginatedResult;
import com.keycloak.common.DbProductCategory;
import com.keycloak.products.entity.CategoryEntity;

import java.util.List;

public interface CategoryService {

    DbProductCategory createCategory(DbProductCategory dbProductCategory);
    DBPaginatedResult getAllCategories(int page, int size, String sortBy, String order);
    DbProductCategory getCategoryById(String id);
    DbProductCategory updateCategory(DbProductCategory dbProductCategory, String categoryId);
    String deleteCategory(String id);
    String removeSubCategory(String parentCategoryId, String subCategoryId);

    List<CategoryEntity> getSubCategories(List<String> categoryIds);


}
