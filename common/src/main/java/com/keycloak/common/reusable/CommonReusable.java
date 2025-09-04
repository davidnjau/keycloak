
package com.keycloak.common.reusable;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.data.web.SpringDataWebProperties;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class CommonReusable {

    /**
     * Creates a Pageable object for pagination and sorting of data.
     *
     * @param page   The page number (zero-based) to retrieve.
     * @param size   The number of items per page.
     * @param sortBy The field name to sort by.
     * @param order  The sort order, either "asc" for ascending or "desc" for descending.
     * @return A Pageable object configured with the specified pagination and sorting parameters.
     */
    public Pageable getPageable(int page, int size, String sortBy, String order) {

        log.info("Creating Pageable on common with page={}, size={}, sortBy={}, order={}", page, size, sortBy, order);
        // Default sort field if not provided
        String sortField = (sortBy == null || sortBy.isBlank()) ? "id" : sortBy;

        // Determine sort direction
        Sort.Direction direction =
                (order != null && order.equalsIgnoreCase("desc"))
                        ? Sort.Direction.DESC
                        : Sort.Direction.ASC;

        Sort sort = Sort.by(direction, sortField);
        return PageRequest.of(page, size, sort);
    }
}
