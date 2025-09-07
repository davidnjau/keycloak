package com.keycloak.products.repository;

import com.keycloak.products.entity.ProductImageEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ProductImageEntityRepository extends JpaRepository<ProductImageEntity, Long> {

    Optional<ProductImageEntity> findByStorageIdAndProductId(String storageId, String productId);

}
