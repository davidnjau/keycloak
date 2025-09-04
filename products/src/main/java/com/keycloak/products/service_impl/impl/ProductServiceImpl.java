package com.keycloak.products.service_impl.impl;

import com.keycloak.products.entity.CategoryEntity;
import com.keycloak.products.entity.ProductEntity;
import com.keycloak.products.repository.CategoryRepository;
import com.keycloak.products.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;

/**
 * Service layer for managing products.
 */
@Service
@RequiredArgsConstructor
public class ProductServiceImpl {

    private final ProductRepository productRepository;
    private final CategoryRepository categoryRepository;

    /**
     * Creates a new product under a specific category.
     *
     * @param name        Product name.
     * @param description Product description.
     * @param price       Product price.
     * @param sku         Product SKU.
     * @param categoryId  Category ID.
     * @return The created Product.
     */
    public ProductEntity createProduct(String name, String description, BigDecimal price, String sku, Long categoryId) {
        CategoryEntity categoryEntity = categoryRepository.findById(categoryId)
                .orElseThrow(() -> new IllegalArgumentException("Category not found"));

        ProductEntity productEntity = new ProductEntity();
        productEntity.setName(name);
        productEntity.setDescription(description);
        productEntity.setOldPrice(price);
        productEntity.setSku(sku);
        productEntity.setCategoryEntity(categoryEntity);

        return productRepository.save(productEntity);
    }

    /**
     * Finds all products in a given category.
     */
//    public List<ProductEntity> getProductsByCategory(Long categoryId) {
//        return productRepository.findByCategoryId(categoryId);
//    }
}