package com.keycloak.products.service_impl.impl;

import com.keycloak.products.entity.CategoryEntity;
import com.keycloak.products.repository.CategoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Service layer for managing categories.
 */
@Service
@RequiredArgsConstructor
public class CategoryServiceImpl {

    private final CategoryRepository categoryRepository;

    /**
     * Creates a new category under an optional parent.
     *
     * @param name     Name of the category.
     * @param parentId Parent category ID (null for root).
     * @return The created Category.
     */
    public CategoryEntity createCategory(String name, Long parentId) {
        CategoryEntity categoryEntity = new CategoryEntity();
        categoryEntity.setName(name);

        if (parentId != null) {
            CategoryEntity parent = categoryRepository.findById(parentId)
                    .orElseThrow(() -> new IllegalArgumentException("Parent not found"));
            categoryEntity.setParent(parent);
            categoryEntity.setPath(parent.getPath()); // temporary
        }

        // Save initial to generate ID
        CategoryEntity saved = categoryRepository.save(categoryEntity);

        // Update path correctly
        if (saved.getParent() != null) {
            saved.setPath(saved.getParent().getPath() + saved.getId() + "/");
        } else {
            saved.setPath("/" + saved.getId() + "/");
        }

        return categoryRepository.save(saved);
    }

    /**
     * Fetches a category subtree using CTE recursion.
     */
    public List<CategoryEntity> getSubtree(Long categoryId) {
        return categoryRepository.findSubtree(categoryId);
    }

    /**
     * Fetches a category subtree using materialized path.
     */
    public List<CategoryEntity> getSubtreeUsingPath(Long categoryId) {
        return categoryRepository.findSubtreeByPath(categoryId);
    }
}
