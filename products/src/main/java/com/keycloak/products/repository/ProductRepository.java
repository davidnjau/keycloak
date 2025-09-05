package com.keycloak.products.repository;

import com.keycloak.products.entity.ProductEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing Product persistence.
 */
public interface ProductRepository extends JpaRepository<ProductEntity, Long> {

    Page<ProductEntity> findByActive(boolean active, Pageable pageable);
    Optional<ProductEntity> findById(String productId);
}
