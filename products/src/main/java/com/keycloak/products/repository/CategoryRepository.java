package com.keycloak.products.repository;

import com.keycloak.products.entity.CategoryEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing Category persistence.
 */
public interface CategoryRepository extends JpaRepository<CategoryEntity, Long> {

    /**
     * Fetches the subtree of a given category using a recursive CTE.
     *
     * @param categoryId The root category ID.
     * @return List of categories in the subtree (including the root).
     */
    @Query(value = """
        WITH RECURSIVE category_tree AS (
            SELECT * FROM categories WHERE id = :categoryId
            UNION ALL
            SELECT c.* FROM categories c
            INNER JOIN category_tree ct ON c.parent_id = ct.id
        )
        SELECT * FROM category_tree;
        """, nativeQuery = true)
    List<CategoryEntity> findSubtree(@Param("categoryId") Long categoryId);

    /**
     * Fetches the subtree of a given category using the materialized path.
     *
     * @param categoryId The root category ID.
     * @return List of categories in the subtree (including the root).
     */
    @Query(value = """
        SELECT * FROM categories
        WHERE path LIKE CONCAT((SELECT path FROM categories WHERE id = :categoryId), '%')
        """, nativeQuery = true)
    List<CategoryEntity> findSubtreeByPath(@Param("categoryId") Long categoryId);

    Optional<CategoryEntity> findByName(String name);
    Optional<CategoryEntity> findById(String id);
    Page<CategoryEntity> findByActive(boolean active, Pageable pageable);
}
