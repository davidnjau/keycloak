package com.keycloak.common.utils;

import java.util.ArrayList;
import java.util.List;

public class PathUtils {

    public static String truncatePath(String path, String cutoffUuid) {
        if (path == null || path.isEmpty()) {
            return path;
        }

        // Split and remove empty strings from leading/trailing slashes
        String[] partsArray = path.split("/");
        List<String> parts = new ArrayList<>();
        for (String part : partsArray) {
            if (!part.isBlank()) {
                parts.add(part);
            }
        }

        // Find index of the cutoff UUID
        int cutoffIndex = parts.indexOf(cutoffUuid);

        // If the cutoff UUID is not found, return the original path
        if (cutoffIndex == -1) {
            return path;
        }

        // Remove everything from cutoff onwards
        parts = parts.subList(0, cutoffIndex);

        // Reconstruct the path with leading and trailing slashes
        return "/" + String.join("/", parts) + "/";
    }
}
