package com.keycloak.products.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    private BigDecimal newPrice;

    /**
     * New Price currency.
     */
    private String newPriceCurrency;

    /**
     * Stock Keeping Unit (SKU) identifier.
     * Internal fingerprint within your business
     */
    @Column(unique = true)
    private String sku;

    /**
     * Indicates whether the product is active or not.
     */
    @Column
    private Boolean active = true;

    /**
     * Available stock quantity (units not yet reserved).
     */
    private Integer availableQuantity = 0;

    /**
     * Reserved stock quantity (units reserved in carts/orders).
     */
    private Integer reservedQuantity = 0;

    /**
     * A product can belong to multiple categories.
     */
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "product_category",
            joinColumns = @JoinColumn(name = "product_id"),
            inverseJoinColumns = @JoinColumn(name = "category_id")
    )
    private Set<CategoryEntity> categories = new HashSet<>();

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

    /**
     * Attributes are stored as PostgreSQL text[] array.
     * Example: {"popular","seasonal","discounted"}
     */
    @ElementCollection
    private List<String> tags; // or use List<String>


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
