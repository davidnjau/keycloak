package com.keycloak.products.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Product entity represents items in the catalog.
 * Each product belongs to a category.
 */
@Entity
@Table(name = "product")
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
    @Column(columnDefinition = "TEXT")
    private String description;

    /**
     * Old Price of the product.
     */
    @Column(nullable = false)
    private BigDecimal oldPrice;

    /**
     * Old Price currency.
     */
    @Column(nullable = false)
    private String oldPriceCurrency;


    /**
     * New Price of the product.
     */
    @Column(nullable = false)
    private BigDecimal newPrice;

    /**
     * New Price currency.
     */
    @Column(nullable = false)
    private String newPriceCurrency;

    /**
     * Stock Keeping Unit (SKU) identifier.
     */
    @Column(unique = true, nullable = false)
    private String sku;

    /**
     * Available stock quantity (units not yet reserved).
     */
    @Column(nullable = false)
    private Integer availableQuantity = 0;

    /**
     * Reserved stock quantity (units reserved in carts/orders).
     */
    @Column(nullable = false)
    private Integer reservedQuantity = 0;

    /**
     * Reference to the category this product belongs to.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", nullable = false)
    private CategoryEntity categoryEntity;

    /**
     * Associated product images.
     */
    @OneToMany(
            mappedBy = "product",
            cascade = CascadeType.ALL,
            orphanRemoval = true,
            fetch = FetchType.LAZY
    )
    private List<ProductImageEntity> images = new ArrayList<>();

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
