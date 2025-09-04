package com.keycloak.products.service_impl.impl;

import com.keycloak.common.DbProductCategory;
import com.keycloak.common.exception.ConflictException;
import com.keycloak.common.exception.ContentNotFoundException;
import com.keycloak.common.reusable.CommonReusable;
import com.keycloak.products.entity.CategoryEntity;
import com.keycloak.products.repository.CategoryRepository;
import com.keycloak.products.service_impl.service.CategoryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service layer for managing categories.
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class CategoryServiceImpl implements CategoryService {

    private final CategoryRepository categoryRepository;
    private final CommonReusable commonReusable;

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






    @Override
    public String createCategory(DbProductCategory dbProductCategory) {

        log.info("Creating category with name: {}", dbProductCategory.getName());
        //Check if the name exists
        Optional<CategoryEntity> categoryEntity = categoryRepository.findByName(dbProductCategory.getName());
        if (categoryEntity.isPresent()) {
            log.error("Category name already exists: {}", dbProductCategory.getName());
            throw new ConflictException("Category name already exists");
        }

        //Create a new category
        CategoryEntity category = new CategoryEntity();
        category.setName(dbProductCategory.getName());
        category.setDescription(dbProductCategory.getDescription());
        category.setPath(dbProductCategory.getPath());
        if (dbProductCategory.getParentCategoryId()!= null) {
            category.setParent(categoryRepository.findById(
                    dbProductCategory.getParentCategoryId()
            ).orElse(null));
        }
        CategoryEntity saved = categoryRepository.save(category);

        // Update path correctly
        if (saved.getParent() != null) {
            saved.setPath(saved.getParent().getPath() + saved.getId() + "/");
        } else {
            saved.setPath("/" + saved.getId() + "/");
        }

        categoryRepository.save(saved);

        log.info("Category created successfully with ID: {}", saved.getId());

        return "Category has been created successfully.";
    }

    @Override
    public List<DbProductCategory> getAllCategories(int page, int size, String sortBy, String order) {
        log.info("Fetching categories with page={}, size={}, sortBy={}, order={}", page, size, sortBy, order);

        try{

            Pageable pageable = commonReusable.getPageable(page, size, sortBy, order);
            Page<CategoryEntity> result = categoryRepository.findAll(pageable);

            if (result.isEmpty()) {
                log.warn("No categories found for the given pagination request");
                return List.of(); // return empty immutable list
            }

            List<DbProductCategory> categories = result.stream()
                    .filter(Objects::nonNull)
                    .map(this::mapToDbProductCategory)
                    .collect(Collectors.toUnmodifiableList());

            log.info("Successfully fetched {} categories", categories.size());
            return categories;

        }catch (Exception ex){
            log.error("Error fetching categories: {}", ex.getMessage());
            throw new ContentNotFoundException("Error fetching categories");
        }


    }

    private DbProductCategory mapToDbProductCategory(CategoryEntity category) {
        return new DbProductCategory(
                category.getId(),
                category.getName(),
                category.getDescription(),
                category.getPath(),
                category.getParent() == null ? null : category.getParent().getId()
        );
    }



    @Override
    public DbProductCategory getCategoryById(String id) {
        log.info("Fetching category with ID: {}", id);

        Optional<CategoryEntity> categoryEntity = categoryRepository.findById(id);
        if (categoryEntity.isEmpty()) {
            log.error("Category not found with ID: {}", id);
            throw new ContentNotFoundException("Category not found");
        }

        log.info("Successfully fetched category with ID: {}", id);
        return mapToDbProductCategory(categoryEntity.get());

    }

    @Override
    public DbProductCategory updateCategory(DbProductCategory dbProductCategory, String categoryId) {
        log.info("Updating category with ID: {} and new details: {}", categoryId, dbProductCategory);
        CategoryEntity categoryEntity = categoryRepository.findById(categoryId)
                   .orElseThrow(() -> new ContentNotFoundException("Category not found"));

        if (dbProductCategory.getName()!= null) {
            categoryEntity.setName(dbProductCategory.getName());
        }
        if (dbProductCategory.getDescription()!= null) {
            categoryEntity.setDescription(dbProductCategory.getDescription());
        }
        if (dbProductCategory.getPath()!= null) {
            categoryEntity.setPath(dbProductCategory.getPath());
        }
        if (dbProductCategory.getParentCategoryId()!= null) {
            categoryEntity.setParent(categoryRepository.findById(
                    dbProductCategory.getParentCategoryId()
            ).orElse(null));
        }
        CategoryEntity saved = categoryRepository.save(categoryEntity);

        log.info("Category updated successfully with ID: {}", categoryId);
        return mapToDbProductCategory(saved);
    }

    @Override
    public String deleteCategory(String categoryId) {

        log.info("Soft Deleting category with ID: {}", categoryId);
        CategoryEntity categoryEntity = categoryRepository.findById(categoryId)
                .orElseThrow(() -> new ContentNotFoundException("Category not found"));
        categoryEntity.setActive(false);

        log.info("Category soft deleted successfully with ID: {}", categoryId);
        categoryRepository.save(categoryEntity);

        return "The category has been soft deleted successfully.";
    }
}
