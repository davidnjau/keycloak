package com.keycloak.products.service_impl.impl;

import com.keycloak.common.DBPaginatedResult;
import com.keycloak.common.DbProduct;
import com.keycloak.common.DbProductCategory;
import com.keycloak.common.DbProductImage;
import com.keycloak.common.exception.BadRequestException;
import com.keycloak.common.exception.ContentNotFoundException;
import com.keycloak.common.reusable.CommonReusable;
import com.keycloak.products.entity.CategoryEntity;
import com.keycloak.products.entity.ProductEntity;
import com.keycloak.products.entity.ProductImageEntity;
import com.keycloak.products.repository.CategoryRepository;
import com.keycloak.products.repository.ProductRepository;
import com.keycloak.products.service_impl.service.CategoryService;
import com.keycloak.products.service_impl.service.ProductService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service layer for managing products.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;
    private final CategoryService categoryService;
    private final CommonReusable commonReusable;


    @Override
    public DbProduct createProduct(DbProduct dbProduct) {

        log.info("Creating new product: {}", dbProduct);
        List<ProductImageEntity> imageEntities = Objects
                .requireNonNull(dbProduct.getProductImages())
                .stream()
                .map(this::mapProductImageEntity)
                .toList();

        log.info("Creating images for product: {}", dbProduct.getName());
        //Get the category entities from the category ids
        List<CategoryEntity> categoryEntities = categoryService.getSubCategories(dbProduct.getCategoryIds());

        // Convert List -> Set
        Set<CategoryEntity> categories = new HashSet<>(categoryEntities);

        ProductEntity productEntity = new ProductEntity();
        // Map the DbProduct to ProductEntity
        // Set the product entity properties
        // Save the product entity to the database
        productEntity.setName(dbProduct.getName());
        productEntity.setDescription(dbProduct.getDescription());
        productEntity.setOldPrice(dbProduct.getOldPrice());
        productEntity.setOldPriceCurrency(dbProduct.getOldPriceCurrency());
        productEntity.setNewPrice(dbProduct.getNewPrice());
        productEntity.setNewPriceCurrency(dbProduct.getNewPriceCurrency());
        productEntity.setAvailableQuantity(dbProduct.getAvailableQuantity());
        productEntity.setReservedQuantity(dbProduct.getReservedQuantity());
        productEntity.setCategories(categories);
        productEntity.setSku(dbProduct.getSku());

        productEntity.setTags(dbProduct.getTags());

        log.info("Saving product: {}", dbProduct.getName());

        ProductEntity savedProductEntity = productRepository.save(productEntity);
        savedProductEntity.setImages(imageEntities);

        log.info("Product saved with ID: {}", savedProductEntity.getId());
        productRepository.save(savedProductEntity);

        return dbProduct;
    }

    private ProductImageEntity mapProductImageEntity(@NotNull DbProductImage dbImage) {

        log.info("Mapping DbProductImage to ProductImageEntity: {}", dbImage);

        ProductImageEntity entity = new ProductImageEntity();
        entity.setUrl(dbImage.getImageUrl());
        entity.setAltText(dbImage.getMetadata());
        entity.setSortOrder(dbImage.getSortOrder());
        entity.setStorageId(dbImage.getStorageId());
        entity.setValid(Boolean.TRUE.equals(dbImage.isValid()));

        // If ProductImageEntity has a relation back to ProductEntity, set it later
        return entity;

    }

    @Override
    public DBPaginatedResult getProducts(int page, int size, String sortBy, String order, boolean isActive) {
        log.info("Fetching products with page={}, size={}, sortBy={}, order={}", page, size, sortBy, order);

        try{

            Pageable pageable = commonReusable.getPageable(page, size, sortBy, order);
            Page<ProductEntity> result = productRepository.findByActive(isActive, pageable);

            log.info("Total number of products: {}", result.getTotalElements());

            if (result.isEmpty()) {
                log.info("No products found");
                throw new ContentNotFoundException("No products found");
            }

            List<DbProduct> dbProductList = result.getContent().stream()
                    .map(this::mapProductEntityToDbProduct)
                   .toList();

            log.info("Returning products: {}", dbProductList.size());

            DBPaginatedResult dBPaginatedResult = new DBPaginatedResult(
                    dbProductList.size(),
                    page,
                    size,
                    0,
                    dbProductList
            );

            log.info("Successfully fetched {} categories", dbProductList.size());
            return dBPaginatedResult;

        }catch (Exception e){
            log.error("Error fetching products: ", e);
            throw new ContentNotFoundException("Error fetching products");
        }

    }

    private DbProduct mapProductEntityToDbProduct(ProductEntity productEntity) {

        log.info("Mapping ProductEntity to DbProduct: {}", productEntity);

        List<DbProductImage> productImages = productEntity.getImages().stream()
                .map(this::mapProductImageEntityToDbProductImage)
                .collect(Collectors.toList());

        Set<CategoryEntity> categories = productEntity.getCategories();
        List<String> categoryIds = categories.stream()
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

    private DbProductImage mapProductImageEntityToDbProductImage(ProductImageEntity productImageEntity) {

        log.info("Mapping ProductImageEntity to DbProductImage: {}", productImageEntity);

        return new DbProductImage(
                productImageEntity.getId(),
                productImageEntity.getUrl(),
                productImageEntity.getAltText(),
                productImageEntity.getSortOrder(),
                productImageEntity.getStorageId(),
                productImageEntity.isValid(),
                productImageEntity.getProduct().getId()
        );

    }

    @Override
    public DbProduct getProductById(String productId) {

        log.info("Fetching product with ID: {}", productId);
        Optional<ProductEntity> optionalProductEntity = productRepository.findById(productId);
        if (optionalProductEntity.isEmpty()){
            getProductNotFound(productId);
            throw new ContentNotFoundException("Product not found");
        }
        return mapProductEntityToDbProduct(optionalProductEntity.get());

    }

    private static void getProductNotFound(String productId) {
        log.error("Product not found with ID: {}", productId);
    }

    @Override
    public DbProduct updateProduct(DbProduct dbProduct, String productId) {

        log.info("Updating product with ID: {}", productId);

        Optional<ProductEntity> optionalProductEntity = productRepository.findById(productId);
        if (optionalProductEntity.isEmpty()){
            getProductNotFound(productId);
            throw new ContentNotFoundException("Product not found");
        }
        ProductEntity productEntity = optionalProductEntity.get();

        if (dbProduct.getName()!= null) productEntity.setName(dbProduct.getName());
        if (dbProduct.getDescription()!= null) productEntity.setDescription(dbProduct.getDescription());
        if (dbProduct.getOldPrice()!= null) productEntity.setOldPrice(dbProduct.getOldPrice());
        if (dbProduct.getOldPriceCurrency()!= null) productEntity.setOldPriceCurrency(dbProduct.getOldPriceCurrency());
        if (dbProduct.getNewPrice()!= null) productEntity.setNewPrice(dbProduct.getNewPrice());
        if (dbProduct.getNewPriceCurrency()!= null) productEntity.setNewPriceCurrency(dbProduct.getNewPriceCurrency());
        if (dbProduct.getAvailableQuantity()!= null) productEntity.setAvailableQuantity(dbProduct.getAvailableQuantity());
        if (dbProduct.getReservedQuantity()!= null) productEntity.setReservedQuantity(dbProduct.getReservedQuantity());
        if (dbProduct.getSku()!= null) productEntity.setSku(dbProduct.getSku());
        if (dbProduct.getTags()!= null) productEntity.setTags(dbProduct.getTags());
        if (dbProduct.isActive() != null) productEntity.setActive(Boolean.TRUE.equals(dbProduct.isActive()));

        if (dbProduct.getProductImages()!= null) {

            List<DbProductImage> imageList = dbProduct.getProductImages();
            for (int i = 0; i < imageList.size(); i++) {
                ProductImageEntity productImageEntity = getProductImageEntity(imageList, i);

                productEntity.getImages().add(productImageEntity);
            }

        }

        if (dbProduct.getCategoryIds()!= null){

            List<String> categoryIds = dbProduct.getCategoryIds();
            List<CategoryEntity> categoryList = categoryService.getSubCategories(categoryIds);
            if (!categoryList.isEmpty()){
                productEntity.getCategories().addAll(categoryList);
            }
        }

        log.info("Update products");
        productRepository.save(productEntity);

        return dbProduct;
    }

    @NotNull
    private static ProductImageEntity getProductImageEntity(List<DbProductImage> imageList, int i) {
        DbProductImage dbProductImage = imageList.get(i);
        ProductImageEntity productImageEntity = new ProductImageEntity();

        if (dbProductImage.getId()!= null) productImageEntity.setId(dbProductImage.getId());
        if (dbProductImage.getImageUrl()!= null) productImageEntity.setUrl(dbProductImage.getImageUrl());
        if (dbProductImage.getMetadata()!= null) productImageEntity.setAltText(dbProductImage.getMetadata());
        if (dbProductImage.getSortOrder()!= null) productImageEntity.setSortOrder(dbProductImage.getSortOrder());
        if (dbProductImage.getStorageId()!= null) productImageEntity.setStorageId(dbProductImage.getStorageId());
        if (dbProductImage.isValid()!= null) productImageEntity.setValid(Boolean.TRUE.equals(dbProductImage.isValid()));
        return productImageEntity;
    }

    @Override
    public String deleteProduct(String productId) {

        log.info("Deleting product with ID: {}", productId);

        Optional<ProductEntity> optionalProductEntity = productRepository.findById(productId);
        if (optionalProductEntity.isEmpty()){
            getProductNotFound(productId);
            throw new ContentNotFoundException("Product not found");
        }

        ProductEntity productEntity = optionalProductEntity.get();
        productEntity.setActive(false);

        productRepository.save(productEntity);
        log.info("Product with ID: {} has been soft deleted", productId);


        return "Product has been deleted";
    }

    @Override
    public String addProductToCategory(String productId, List<String> categoryIds) {

        log.info("Adding product with ID: {} to category with ID: {}", productId, categoryIds);
        // Add code to add product to category

        getFetchProductAndCategoryEntitiesLog();
        Optional<ProductEntity> optionalProductEntity = productRepository.findById(productId);
        if (optionalProductEntity.isEmpty()){
            getProductNotFound(productId);
            throw new ContentNotFoundException("Product not found");
        }
        ProductEntity productEntity = optionalProductEntity.get();

        getFetchCategoryEntitiesLogs();
        List<CategoryEntity> categoryEntities = categoryService.getSubCategories(categoryIds);
        if (categoryEntities.isEmpty()){
            getCategoryErrorLog(categoryIds);
            throw new ContentNotFoundException("No category found");
        }

        // Convert List -> Set
        Set<CategoryEntity> categories = new HashSet<>(categoryEntities);
        productEntity.setCategories(categories);

        // Save changes to database
        log.info("Product with ID: {} has been added to categories: {}", productId, categoryIds);
        productRepository.save(productEntity);
        return "Product has been added to category";

    }

    private static void getCategoryErrorLog(List<String> categoryIds) {
        log.error("No category found with ID: {}", categoryIds);
    }

    private static void getFetchCategoryEntitiesLogs() {
        log.info("Fetch category entities");
    }

    private static void getFetchProductAndCategoryEntitiesLog() {
        log.info("Fetch product and category entities");
    }

    @Override
    public String removeProductFromCategory(String productId, List<String> categoryIds) {

        log.info("Removing product with ID: {} from category with ID: {}", productId, categoryIds);
        // Add code to remove product from category

        getFetchProductAndCategoryEntitiesLog();
        Optional<ProductEntity> optionalProductEntity = productRepository.findById(productId);
        if (optionalProductEntity.isEmpty()){
            getProductNotFound(productId);
            throw new ContentNotFoundException("Product not found");
        }
        ProductEntity productEntity = optionalProductEntity.get();

        getFetchCategoryEntitiesLogs();
        List<CategoryEntity> categoryEntities = categoryService.getSubCategories(categoryIds);
        if (categoryEntities.isEmpty()){
            getCategoryErrorLog(categoryIds);
            throw new ContentNotFoundException("No category found");
        }

        // Convert List -> Set
        Set<CategoryEntity> categories = new HashSet<>(categoryEntities);

        // Remove categories from product
        productEntity.getCategories().removeAll(categories);

        // Save changes to database
        log.info("Product with ID: {} has been removed from categories: {}", productId, categoryIds);
        productRepository.save(productEntity);

        return "Product has been removed from category";
    }


}