
package com.keycloak.common.reusable;

import org.springframework.boot.autoconfigure.data.web.SpringDataWebProperties;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

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
        Sort sort = order.equalsIgnoreCase("desc")?
                Sort.by(sortBy).descending() :
                Sort.by(sortBy).ascending();

        return PageRequest.of(page, size, sort);
    }
}
