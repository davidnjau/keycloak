package com.keycloak.products.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;
import org.hibernate.annotations.Type;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Category entity represents hierarchical categories in the product catalog.
 * Categories support unlimited depth using an adjacency list model (parent-child)
 * and a materialized path for optimized subtree queries.
 */
@Entity
@Table(name = "categories")
@Getter
@Setter
@NoArgsConstructor
public class CategoryEntity {

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
     * Name of the category (e.g., "Electronics", "Smartphones").
     */
    @Column(nullable = false)
    private String name;

    /**
     * Description for accessibility and SEO.
     */
    @Column(length = 255)
    private String description;

    /**
     * Parent category reference. Null for root categories.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private CategoryEntity parent;

    /**
     * Children of this category. Bidirectional mapping.
     */
    @OneToMany(mappedBy = "parent", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<CategoryEntity> children = new ArrayList<>();

    /**
     * Materialized path for efficient subtree lookups.
     * Example: /1/2/5/ indicates hierarchy from root -> subcategory -> current.
     */
    @Column(columnDefinition = "TEXT")
    private String path;

    /**
     * Indicates whether the category is active or not.
     */
    @Column
    private Boolean active = true;

    /**
     * Attributes are stored as PostgreSQL text[] array.
     * Example: {"popular","seasonal","discounted"}
     */
    @ElementCollection
    private List<String> attributes; // or use List<String>


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
