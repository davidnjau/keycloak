package com.keycloak.products.service_impl.service;

import com.keycloak.common.DBPaginatedResult;
import com.keycloak.common.DbProduct;

import java.util.List;

public interface ProductService {

    DbProduct createProduct(DbProduct dbProduct);
    DBPaginatedResult getProducts(int page, int size, String sortBy, String order, boolean isActive);
    DbProduct getProductById(String id);
    DbProduct updateProduct(DbProduct dbProduct, String productId);
    String deleteProduct(String id);
    String addProductToCategory(String productId, List<String> categoryIds);
    String removeProductFromCategory(String productId, List<String> categoryIds);

}
