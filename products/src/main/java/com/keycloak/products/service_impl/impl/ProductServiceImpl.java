package com.keycloak.products.service_impl.impl;

import com.keycloak.common.*;
import com.keycloak.common.exception.BadRequestException;
import com.keycloak.common.exception.ConflictException;
import com.keycloak.common.exception.ContentNotFoundException;
import com.keycloak.common.reusable.CommonReusable;
import com.keycloak.products.entity.CategoryEntity;
import com.keycloak.products.entity.ProductEntity;
import com.keycloak.products.entity.ProductImageEntity;
import com.keycloak.products.repository.CategoryRepository;
import com.keycloak.products.repository.ProductImageEntityRepository;
import com.keycloak.products.repository.ProductRepository;
import com.keycloak.products.service_impl.service.CategoryService;
import com.keycloak.products.service_impl.service.ProductService;
import com.keycloak.products.utility.ProductMapper;
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
    private final ProductImageEntityRepository productImageEntityRepository;
    private final CommonReusable commonReusable;
    private final ProductMapper productMapper;
    private final CategoryRepository categoryRepository;


    @Override
    public DbProduct createProduct(DbProduct dbProduct) {

        log.info("Creating new product: {}", dbProduct);

        String sku = dbProduct.getSku();
        if (sku == null || sku.isEmpty()) {
            throw new BadRequestException("Product SKU cannot be null or empty");
        }
        Optional<ProductEntity> optionalSku = productRepository.findBySku(sku);
        if (optionalSku.isPresent()) {
            throw new ConflictException("Product SKU already exists: " + sku);
        }

        log.info("Creating images for product: {}", dbProduct.getName());
        //Get the category entities from the category ids
        List<CategoryEntity> categoryEntities = getSubCategories(dbProduct.getCategoryIds());

        // Convert List -> Set

        ProductEntity productEntity = new ProductEntity();
        // Map the DbProduct to ProductEntity
        // Set the product entity properties
        // Save the product entity to the database

        if (dbProduct.getName() != null) productEntity.setName(dbProduct.getName());
        if (dbProduct.getDescription()!= null) productEntity.setDescription(dbProduct.getDescription());
        if (dbProduct.getOldPrice()!= null) productEntity.setOldPrice(dbProduct.getOldPrice());
        if (dbProduct.getOldPriceCurrency()!= null) productEntity.setOldPriceCurrency(dbProduct.getOldPriceCurrency());
        if (dbProduct.getNewPrice()!= null) productEntity.setNewPrice(dbProduct.getNewPrice());
        if (dbProduct.getNewPriceCurrency()!= null) productEntity.setNewPriceCurrency(dbProduct.getNewPriceCurrency());
        if (dbProduct.getAvailableQuantity()!= null) productEntity.setAvailableQuantity(dbProduct.getAvailableQuantity());
        if (dbProduct.getReservedQuantity()!= null) productEntity.setReservedQuantity(dbProduct.getReservedQuantity());
        if (!categoryEntities.isEmpty()){
            Set<CategoryEntity> categories = new HashSet<>(categoryEntities);
            productEntity.setCategories(categories);
        }
        if (dbProduct.getSku()!= null) productEntity.setSku(dbProduct.getSku());
        if (dbProduct.getTags()!= null) productEntity.setTags(dbProduct.getTags());

        log.info("Saving product: {}", dbProduct.getName());
        productRepository.save(productEntity);

        //Update Images


        updateProductImages("create",productEntity, dbProduct.getProductImages());


        dbProduct.setId(productEntity.getId());

        return dbProduct;
    }

    private List<CategoryEntity> getSubCategories(List<String> categoryIds) {

        if (categoryIds == null || categoryIds.isEmpty()) {
            return Collections.emptyList();
        }

        // Fetch all categories in one query (avoids N+1 problem)

        // Map entities -> DTOs
        return categoryRepository.findAllByIdInAndActiveTrue(categoryIds);

    }

    private ProductImageEntity mapProductImageEntity(@NotNull DbProductImage dbImage) {

        log.info("Mapping DbProductImage to ProductImageEntity: {}", dbImage);

        ProductImageEntity entity = new ProductImageEntity();
        entity.setUrl(dbImage.getImageUrl());
        entity.setAltText(dbImage.getMetadata());
        entity.setSortOrder(dbImage.getSortOrder());
        entity.setStorageId(dbImage.getStorageId());
        Boolean isValid = dbImage.isValid();
        entity.setValid(isValid == null || isValid);

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

            List<DbProduct> dbProductList =result.getContent().stream()
                    .map(productMapper::mapProductEntityToDbProduct)
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

        return productMapper.mapProductEntityToDbProduct(optionalProductEntity.get());

    }

    private static void getProductNotFound(String productId) {
        log.error("Product not found with ID: {}", productId);
    }

    @Override
    public DbProduct updateProduct(DbProduct dbProduct, String productId) {

        Optional<ProductEntity> optionalProductEntity = productRepository.findById(productId);
        if (optionalProductEntity.isEmpty()){
            getProductNotFound(productId);
            throw new ContentNotFoundException("Product not found");
        }
        try{

            log.info("Updating product with ID: {}", productId);
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
            if (dbProduct.isActive() != null) productEntity.setActive(Boolean.TRUE.equals(dbProduct.isActive()));

            productRepository.save(productEntity);

            // ✅ Merge Tags
            if (dbProduct.getTags() != null) {
                List<String> updateTagList = dbProduct.getTags();
                List<String> currentTagList = productEntity.getTags();

                // Initialize mutable if null
                if (currentTagList == null) {
                    currentTagList = new ArrayList<>();
                    productEntity.setTags(currentTagList);
                }

                // Add missing tags
                for (String tag : updateTagList) {
                    if (!currentTagList.contains(tag)) {
                        currentTagList.add(tag);
                    }
                }

                // Remove tags that are no longer present
                currentTagList.removeIf(tag -> !updateTagList.contains(tag));
            }

            // ✅ Merge Categories
            if (dbProduct.getCategoryIds() != null && !dbProduct.getCategoryIds().isEmpty()) {
                List<CategoryEntity> categoryList = getSubCategories(dbProduct.getCategoryIds());
                if (!categoryList.isEmpty()) {
                    productEntity.getCategories().addAll(categoryList);
                }
            }

            //Update Images
            updateProductImages("update",productEntity, dbProduct.getProductImages());

            log.info("Update products -> {}", productEntity.getName());
            productRepository.save(productEntity);


            return dbProduct;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }


    }

    private void updateProductImages(String action, ProductEntity productEntity, List<DbProductImage> dbProductImages) {
        if (dbProductImages == null || dbProductImages.isEmpty()) {
            return;
        }

        switch (action.toLowerCase()) {
            case "update":
                for (DbProductImage dbProductImage : dbProductImages) {
                    ProductImageEntity imageEntity = null;

                    // 1. If ID exists, try to find by ID
                    if (dbProductImage.getId() != null) {
                        imageEntity = productImageEntityRepository.findById(dbProductImage.getId()).orElse(null);
                    }

                    // 2. If still not found, try to find by storageId + productId
                    if (imageEntity == null && dbProductImage.getStorageId() != null) {
                        imageEntity = productImageEntityRepository
                                .findByStorageIdAndProductId(dbProductImage.getStorageId(), productEntity.getId())
                                .orElse(null);
                    }

                    if (imageEntity != null) {
                        // ✅ Update existing entity
                        updateProductImage(imageEntity, dbProductImage);
                    } else {
                        // ✅ Create new
                        imageEntity = mapProductImageEntity(dbProductImage);
                        imageEntity.setProduct(productEntity); // maintain back-reference
                        productEntity.getImages().add(imageEntity); // attach to parent for cascade
                    }
                }

                // ✅ Regularize sort orders after all updates
                normalizeImageSortOrders(productEntity);
                break;

            case "create":
                for (DbProductImage dbProductImage : dbProductImages) {
                    if (dbProductImage.getStorageId() != null) {

                        // ✅ Prevent duplicates for same product
                        boolean exists = productEntity.getImages().stream()
                                .anyMatch(img -> dbProductImage.getStorageId()
                                        .equals(img.getStorageId()
                                        )
                                );

                        if (exists) {
                            log.warn("Duplicate image ignored for product {} with storageId {}", productEntity.getId(), dbProductImage.getStorageId());
                            continue; // skip duplicate
                        }

                        ProductImageEntity newImage = mapProductImageEntity(dbProductImage);
                        newImage.setProduct(productEntity);
                        productEntity.getImages().add(newImage);
                    }

                }

                // ✅ Regularize sort orders after creation
                normalizeImageSortOrders(productEntity);
                break;

            default:
                throw new UnsupportedOperationException("Unsupported action: " + action);
        }
    }

    private void updateProductImage(ProductImageEntity productImageEntity, DbProductImage dbProductImage) {
        if (dbProductImage.getImageUrl() != null) productImageEntity.setUrl(dbProductImage.getImageUrl());
        if (dbProductImage.getMetadata() != null) productImageEntity.setAltText(dbProductImage.getMetadata());
        if (dbProductImage.getSortOrder() != null) productImageEntity.setSortOrder(dbProductImage.getSortOrder());
        if (dbProductImage.getStorageId() != null) productImageEntity.setStorageId(dbProductImage.getStorageId());
        if (dbProductImage.isValid() != null) productImageEntity.setValid(Boolean.TRUE.equals(dbProductImage.isValid()));
        productImageEntityRepository.save(productImageEntity);
    }

    /**
     * Ensures unique, sequential sort orders for all images under a product.
     * Example: 1,2,3...N with no gaps or duplicates.
     */
    private void normalizeImageSortOrders(ProductEntity productEntity) {
        List<ProductImageEntity> images = new ArrayList<>(productEntity.getImages());

        // Sort by current sortOrder (nulls last)
        images.sort(Comparator.comparing(
                ProductImageEntity::getSortOrder,
                Comparator.nullsLast(Integer::compareTo)
        ));

        int order = 1;
        for (ProductImageEntity image : images) {
            image.setSortOrder(order++);
        }

        // Persist normalized sort orders
        productImageEntityRepository.saveAll(images);
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
    public String addProductToCategory(String productId, DbCategories dbCategories) {

        List<String> categoryIds = dbCategories.getCategories();

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
        List<CategoryEntity> categoryEntities = getSubCategories(categoryIds);
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
    public String removeProductFromCategory(String productId, DbCategories dbCategories) {

        List<String> categoryIds = dbCategories.getCategories();

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
        List<CategoryEntity> categoryEntities = getSubCategories(categoryIds);
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