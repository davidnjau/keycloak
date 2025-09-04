package com.keycloak.products.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Product entity represents items in the catalog.
 * Each product belongs to a category.
 */
@Entity
@Table(name = "products")
@Getter
@Setter
@NoArgsConstructor
public class ProductEntity {

    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(
            name = "UUID",
            strategy = "org.hibernate.id.UUIDGenerator",
            parameters = {
                    @org.hibernate.annotations.Parameter(
                            name = "uui_gen_strategy_class",
                            value = "org.hibernate.id.uuid.CustomVersionOneStrategy"
                    )
            }
    )
    @Column(name = "id", updatable = false, nullable = false)
    private String id;

    /**
     * Product name (e.g., "iPhone 15 Pro").
     */
    @Column(nullable = false)
    private String name;

    /**
     * Detailed description of the product.
     */
    @Column(length = 2000)
    private String description;

    /**
     * Old Price of the product.
     */
    @Column(nullable = false)
    private BigDecimal oldPrice;


    /**
     * New Price of the product.
     */
    @Column(nullable = false)
    private BigDecimal newPrice;

    /**
     * Stock Keeping Unit (SKU) identifier.
     */
    @Column(unique = true, nullable = false)
    private String sku;

    /**
     * Reference to the category this product belongs to.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", nullable = false)
    private CategoryEntity categoryEntity;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = createdAt;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
