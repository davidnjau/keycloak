package com.keycloak.products.utility;

import com.keycloak.common.DbProduct;
import com.keycloak.common.DbProductCategory;
import com.keycloak.common.exception.ContentNotFoundException;
import com.keycloak.products.entity.CategoryEntity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

@Component
public class CategoryMapper {

    private final ProductMapper productMapper;

    public CategoryMapper(ProductMapper productMapper) {
        this.productMapper = productMapper;
    }

    public DbProductCategory mapToDbProductCategory(CategoryEntity category) {
        boolean active = Boolean.TRUE.equals(category.getActive());
        if (!active) {
            throw new ContentNotFoundException("Category with ID " + category.getId() + " is inactive");
        }

        List<DbProductCategory> childCategories = category.getChildren().stream()
                .filter(Objects::nonNull)
                .filter(child -> Boolean.TRUE.equals(child.getActive()))
                .map(this::mapToDbProductCategory)  // recursion
                .toList();

        List<DbProduct> dbProductList = category.getProducts().stream()
                .map(productMapper::mapProductEntityToDbProduct)
                .toList();

        return new DbProductCategory(
                category.getId(),
                category.getName(),
                category.getDescription(),
                category.getPath(),
                category.getParent() == null ? null : category.getParent().getId(),
                childCategories,
                category.getAttributes(),
                dbProductList
        );
    }


}

