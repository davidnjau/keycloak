package com.keycloak.products.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "product_images")
@Getter
@Setter
@NoArgsConstructor
public class ProductImageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * URL or path of the image (stored in S3/MinIO/Cloud storage).
     */
    @Column(nullable = false)
    private String url;

    /**
     * Alternative text for accessibility and SEO.
     */
    @Column(columnDefinition = "TEXT")
    private String altText;

    /**
     * Sort order (e.g., 0 = primary image).
     */
    @Column(nullable = false)
    private Integer sortOrder = 0;

    /**
     * Storage id from storage.
     */
    @Column(nullable = false)
    private String storageId;

    /**
     * File validity
     */
    @Column(nullable = false)
    private boolean isValid = true;


    /**
     * Owning product reference.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "product_id", nullable = false)
    private ProductEntity product;
}
