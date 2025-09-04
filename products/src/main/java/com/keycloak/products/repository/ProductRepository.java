package com.keycloak.products.repository;

import com.keycloak.products.entity.ProductEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

/**
 * Repository interface for managing Product persistence.
 */
public interface ProductRepository extends JpaRepository<ProductEntity, Long> {

    /**
     * Finds products by category.
     *
     * @param categoryId Category ID.
     * @return List of products in the category.
     */
    List<ProductEntity> findByCategoryId(Long categoryId);
}
