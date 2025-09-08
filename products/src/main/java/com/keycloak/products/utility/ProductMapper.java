package com.keycloak.products.utility;

import com.keycloak.common.DbProduct;
import com.keycloak.common.DbProductImage;
import com.keycloak.products.entity.CategoryEntity;
import com.keycloak.products.entity.ProductEntity;
import com.keycloak.products.entity.ProductImageEntity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class ProductMapper {

    public DbProduct mapProductEntityToDbProduct(ProductEntity productEntity) {
        List<DbProductImage> productImages = productEntity.getImages().stream()
                .map(this::mapProductImageEntityToDbProductImage)
                .collect(Collectors.toList());

        List<String> categoryIds = productEntity.getCategories().stream()
                .map(CategoryEntity::getId)
                .toList();

        return new DbProduct(
                productEntity.getId(),
                productEntity.getName(),
                productEntity.getDescription(),
                productEntity.getOldPrice(),
                productEntity.getOldPriceCurrency(),
                productEntity.getNewPrice(),
                productEntity.getNewPriceCurrency(),
                productEntity.getAvailableQuantity(),
                productEntity.getReservedQuantity(),
                productImages,
                productEntity.getSku(),
                productEntity.getTags(),
                categoryIds,
                productEntity.getActive()
        );
    }

    private DbProductImage mapProductImageEntityToDbProductImage(ProductImageEntity imageEntity) {
        return new DbProductImage(
                imageEntity.getId(),
                imageEntity.getUrl(),
                imageEntity.getAltText(),
                imageEntity.getSortOrder(),
                imageEntity.getStorageId(),
                imageEntity.isValid(),
                imageEntity.getProduct().getId()
        );
    }
}

