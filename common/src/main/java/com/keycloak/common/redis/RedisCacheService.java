package com.keycloak.common.redis;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

@Service
@Slf4j
@RequiredArgsConstructor
public class RedisCacheService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();



    /* ------------------- Key Operations ------------------- */

    public boolean exists(String key) {
        Boolean result = redisTemplate.hasKey(key);
        return result != null && result;
    }

    public boolean delete(String key) {
        Boolean result = redisTemplate.delete(key);
        return result != null && result;
    }

    public void expire(String key, long timeout, TimeUnit unit) {
        redisTemplate.expire(key, timeout, unit);
    }

    public void expire(String key, Duration duration) {
        redisTemplate.expire(key, duration);
    }

    /* ------------------- Value Operations ------------------- */

    public void setValue(String key, Object value) {
        redisTemplate.opsForValue().set(key, value);
        log.debug("Set value for key: {}", key);
    }

    public void setValue(String key, Object value, long timeout, TimeUnit unit) {
        redisTemplate.opsForValue().set(key, value, timeout, unit);
        log.debug("Set value with TTL for key: {}", key);
    }

    @SuppressWarnings("unchecked")
    public <T> T getValue(String key, Class<T> clazz) {
        Object value = redisTemplate.opsForValue().get(key);
        return clazz.isInstance(value) ? (T) value : null;
    }

    /* ------------------- Hash Operations ------------------- */

    public void putHash(String key, String hashKey, Object value) {
        redisTemplate.opsForHash().put(key, hashKey, value);
    }

    @SuppressWarnings("unchecked")
    public <T> T getHashValue(String key, String hashKey, Class<T> clazz) {
        Object value = redisTemplate.opsForHash().get(key, hashKey);
        return clazz.isInstance(value) ? (T) value : null;
    }

    public Map<Object, Object> getHashEntries(String key) {
        return redisTemplate.opsForHash().entries(key);
    }

    public void deleteHashKey(String key, String hashKey) {
        redisTemplate.opsForHash().delete(key, hashKey);
    }

    /* ------------------- List Operations ------------------- */

    public void pushToList(String key, Object value) {
        redisTemplate.opsForList().rightPush(key, value);
    }

    public List<Object> getListRange(String key, long start, long end) {
        return redisTemplate.opsForList().range(key, start, end);
    }

    public Object popFromList(String key) {
        return redisTemplate.opsForList().leftPop(key);
    }

    /* ------------------- Set Operations ------------------- */

    public void addToSet(String key, Object... values) {
        redisTemplate.opsForSet().add(key, values);
    }

    public Set<Object> getSetMembers(String key) {
        return redisTemplate.opsForSet().members(key);
    }

    public boolean isMemberOfSet(String key, Object value) {
        Boolean result = redisTemplate.opsForSet().isMember(key, value);
        return result != null && result;
    }

    /* ------------------- Counter / Increment ------------------- */

    public Long increment(String key) {
        return redisTemplate.opsForValue().increment(key);
    }

    public Long incrementBy(String key, long delta) {
        return redisTemplate.opsForValue().increment(key, delta);
    }

    public Long decrement(String key) {
        return redisTemplate.opsForValue().decrement(key);
    }

    /**
     * Store a value in Redis under a canonical key and optionally under alias keys
     * that point to the canonical key. Only the canonical key stores the actual object.
     *
     * @param namespace   e.g., "auth:user"
     * @param canonicalId Unique canonical ID (e.g., UUID)
     * @param value       Object to cache
     * @param aliases     Map of aliasType -> aliasValue (e.g., "username" -> "john123")
     * @param ttl         Time-to-live
     */
    public void storeWithAliases(String namespace,
                                 String canonicalId,
                                 Object value,
                                 Map<String, String> aliases,
                                 Duration ttl) {
        String canonicalKey = namespace + ":uuid:" + canonicalId;

        // Store canonical value
        redisTemplate.opsForValue().set(canonicalKey, value, ttl);

        // Store alias references -> canonical key
        if (aliases != null) {
            aliases.forEach((aliasType, aliasValue) -> {
                String aliasKey = namespace + ":" + aliasType + ":" + aliasValue;
                redisTemplate.opsForValue().set(aliasKey, canonicalKey, ttl);
            });
        }

        log.debug("Stored {} with canonical key [{}] and aliases {}", namespace, canonicalKey, aliases);
    }

    /**
     * Retrieve a value using either canonical key or alias.
     * If an alias is provided, it resolves to the canonical key and fetches the object.
     */
    public <T> T getWithAliases(String namespace, String keyType, String keyValue, Class<T> clazz) {
        String key = namespace + ":" + keyType + ":" + keyValue;

        Object raw = redisTemplate.opsForValue().get(key);
        if (raw == null) {
            log.debug("Cache miss for [{}]", key);
            return null;
        }

        // If we hit an alias, resolve canonical
        if (raw instanceof String && ((String) raw).startsWith(namespace)) {
            raw = redisTemplate.opsForValue().get((String) raw);
        }

        if (clazz.isInstance(raw)) {
            return clazz.cast(raw);
        }

        try {
            String json = objectMapper.writeValueAsString(raw);
            return objectMapper.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            log.error("Failed to deserialize cache value for key [{}]", key, e);
            return null;
        }
    }

    /**
     * Delete canonical key and all aliases.
     */
    public void evictWithAliases(String namespace,
                                 String canonicalId,
                                 Map<String, String> aliases) {
        String canonicalKey = namespace + ":uuid:" + canonicalId;
        redisTemplate.delete(canonicalKey);

        if (aliases != null) {
            aliases.forEach((aliasType, aliasValue) -> {
                String aliasKey = namespace + ":" + aliasType + ":" + aliasValue;
                redisTemplate.delete(aliasKey);
            });
        }

        log.debug("Evicted cache for canonical [{}] and aliases {}", canonicalKey, aliases);
    }
}
