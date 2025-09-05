package com.keycloak.products.service_impl.impl;

import com.keycloak.common.DBPaginatedResult;
import com.keycloak.common.DbProductCategory;
import com.keycloak.common.exception.BadRequestException;
import com.keycloak.common.exception.ConflictException;
import com.keycloak.common.exception.ContentNotFoundException;
import com.keycloak.common.reusable.CommonReusable;
import com.keycloak.common.utils.PathUtils;
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

import java.util.*;
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

    @Override
    public DbProductCategory createCategory(DbProductCategory dbProductCategory) {

        log.info("Creating category with name: {}", dbProductCategory.getName());
        //Check if the name exists
        Optional<CategoryEntity> categoryEntity = categoryRepository.findByNameAndActive(dbProductCategory.getName(), true);
        if (categoryEntity.isPresent()) {
            log.error("Category name already exists: {}", dbProductCategory.getName());
            throw new ConflictException("Category name already exists");
        }

        //Create a new category
        CategoryEntity category = new CategoryEntity();

        category.setName(dbProductCategory.getName());
        if (dbProductCategory.getDescription()!= null) {
            category.setDescription(dbProductCategory.getDescription());
        }
//        if (dbProductCategory.getPath()!= null) {
//            category.setPath(dbProductCategory.getPath());
//        }
        if (dbProductCategory.getParentCategoryId()!= null) {
            category.setParent(categoryRepository.findById(
                    dbProductCategory.getParentCategoryId()
            ).orElse(null));
        }
        if (!dbProductCategory.getAttributes().isEmpty()) {
            category.setAttributes(dbProductCategory.getAttributes());
        }
        CategoryEntity saved = categoryRepository.save(category);

        // Update path correctly
//        if (saved.getParent() != null) {
//            saved.setPath(saved.getParent().getPath() + saved.getId() + "/");
//        } else {
//            saved.setPath("/" + saved.getId() + "/");
//        }

        categoryRepository.save(saved);

        log.info("Category created successfully with ID: {}", saved.getId());

        dbProductCategory.setId(saved.getId());

        return dbProductCategory;
    }

    @Override
    public DBPaginatedResult getAllCategories(int page, int size, String sortBy, String order) {
        log.info("Fetching categories with page={}, size={}, sortBy={}, order={}", page, size, sortBy, order);

        try{

            Pageable pageable = commonReusable.getPageable(page, size, sortBy, order);
            Page<CategoryEntity> result = categoryRepository.findByActive(true, pageable);

            log.info("Total number of categories: {}", result.getTotalElements());

            if (result.isEmpty()) {
                log.warn("No categories found for the given pagination request");
                throw new ContentNotFoundException("No categories found");
            }

            List<CategoryEntity> roots = categoryRepository.findAllRootCategoriesWithChildren();
            
            List<DbProductCategory> categories = roots.stream()
                    .map(this::mapToDbProductCategory) // recursive, will fetch children
                    .toList();


            DBPaginatedResult dBPaginatedResult = new DBPaginatedResult(
                    categories.size(),
                    page,
                    size,
                    0,
                    categories
            );

            log.info("Successfully fetched {} categories", categories.size());
            return dBPaginatedResult;

        }catch (Exception ex){
            log.error("Error fetching categories: {}", ex.getMessage());
            throw new ContentNotFoundException("Error fetching categories");
        }


    }

    private List<CategoryEntity> getCategoryChildren(CategoryEntity category) {

        String categoryId = category.getId();
        List<CategoryEntity> children = categoryRepository.findSubtree(categoryId);
        if (children.isEmpty()) {
            log.warn("No children found for category with ID: {}", categoryId);
            throw new ContentNotFoundException("No children found for category with ID " + categoryId);
        }
        return children;
    }

    private DbProductCategory mapToDbProductCategory(CategoryEntity category) {
        boolean active = Boolean.TRUE.equals(category.getActive());
        if (!active) {
            log.warn("Category with ID {} is inactive", category.getId());
            throw new ContentNotFoundException("Category with ID "
                    + category.getId() +
                    " could not be retrieved as it was deleted.");
        }

        // Recursively map children (only active ones)
        List<DbProductCategory> childCategories = category.getChildren().stream()
                .filter(Objects::nonNull)
                .filter(child -> Boolean.TRUE.equals(child.getActive()))
                .map(this::mapToDbProductCategory)  // recursion here
                .collect(Collectors.toList());

        return new DbProductCategory(
                category.getId(),
                category.getName(),
                category.getDescription(),
                category.getPath(),
                category.getParent() == null ? null : category.getParent().getId(),
                childCategories,
                category.getAttributes()
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

        try{

            CategoryEntity categoryEntity = categoryRepository.findById(categoryId)
                    .orElseThrow(() -> new ContentNotFoundException("Category not found"));

            if (dbProductCategory.getName()!= null) {
                categoryEntity.setName(dbProductCategory.getName());
            }
            if (dbProductCategory.getDescription()!= null) {
                categoryEntity.setDescription(dbProductCategory.getDescription());
            }
            if (dbProductCategory.getParentCategoryId()!= null) {
                categoryEntity.setParent(categoryRepository.findById(
                        dbProductCategory.getParentCategoryId()
                ).orElse(null));
            }
            if (!dbProductCategory.getAttributes().isEmpty()) {
                //The list that will be updated must be submitted with the new attributes and old attributes removed / maintained in the database
                categoryEntity.setAttributes(dbProductCategory.getAttributes());
            }

            CategoryEntity saved = categoryRepository.save(categoryEntity);

            // Update path correctly
//            if (dbProductCategory.getParentCategoryId() != null) {
//                saved.setPath(saved.getParent().getPath() + saved.getId() + "/");
//                categoryRepository.save(saved);
//            }

            log.info("Category updated successfully with ID: {}", categoryId);
            return mapToDbProductCategory(saved);

        }catch (Exception exception){
            log.error("Error updating category: {}", exception.getMessage());
            throw new BadRequestException("Error updating category");
        }

    }

    @Override
    @Transactional
    public String deleteCategory(String categoryId) {

        log.info("Soft Deleting category with ID: {}", categoryId);
        CategoryEntity category = categoryRepository.findById(categoryId)
                .orElseThrow(() -> new ContentNotFoundException("Category not found"));

        // Determine if this is a root category
        boolean isRoot = category.getParent() == null;

        if (isRoot) {
            handleRootCategorySoftDelete(category);
        } else {
            handleNonRootCategorySoftDelete(category);
        }

        // Finally, mark the category inactive
        category.setActive(false);
        categoryRepository.save(category);

        // Remove inactive category from paths of all active descendants
        updatePathsForActiveDescendants(category);

        return "The category has been soft deleted successfully.";
    }

    private void handleRootCategorySoftDelete(CategoryEntity category) {
        // Promote immediate children to root
        String newParentPath = "/"; // root path
        categoryRepository.bulkUpdateImmediateChildrenParentAndPath(
                category.getId(),
                null,
                newParentPath
        );
    }

    private void handleNonRootCategorySoftDelete(CategoryEntity category) {
        CategoryEntity parent = category.getParent(); // new parent for immediate children
        String newParentPath = parent != null ? parent.getPath() : "/";


        // Update immediate children to point to the parent of the deleted category
        categoryRepository.bulkUpdateImmediateChildrenParentAndPath(
                category.getId(),
                parent,
                newParentPath
        );
    }

    private void updatePathsForActiveDescendants(CategoryEntity category) {
        List<CategoryEntity> descendants = categoryRepository.findAllActiveDescendants(category.getPath());

        for (CategoryEntity descendant : descendants) {
            String updatedPath = descendant.getPath().replace("/" + category.getId() + "/", "/");
//            descendant.setPath(updatedPath);
        }

        categoryRepository.saveAll(descendants);
    }




    @Override
    @Transactional
    public String removeSubCategory(String parentCategoryId, String subCategoryId) {

        CategoryEntity parentCategory = categoryRepository.findById(parentCategoryId)
                .orElseThrow(() -> new ContentNotFoundException("Parent category not found"));

        CategoryEntity subCategory = categoryRepository.findById(subCategoryId)
                .orElseThrow(() -> new ContentNotFoundException("Sub-category not found"));

        // Check if it is actually a child of this parent
        if (!parentCategory.getChildren().remove(subCategory)) {
            throw new BadRequestException("Sub-category does not belong to the parent category");
        }

        parentCategory.setPath(null);

        // Save updates (depending on cascade config, child may be orphaned or deleted)
        categoryRepository.save(parentCategory);

        return "The sub-category has been removed successfully from the parent category.";

    }

    @Override
    public List<CategoryEntity> getSubCategories(List<String> categoryIds) {

        if (categoryIds == null || categoryIds.isEmpty()) {
            return Collections.emptyList();
        }

        // Fetch all categories in one query (avoids N+1 problem)

        // Map entities -> DTOs
        return categoryRepository.findAllByIdInAndActiveTrue(categoryIds);

    }
}
