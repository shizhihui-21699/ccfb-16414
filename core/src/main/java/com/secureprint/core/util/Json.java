package com.secureprint.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/** Single, consistently configured JSON codec used by every module. */
public final class Json {

    private static final ObjectMapper MAPPER = create();

    private Json() {
    }

    private static ObjectMapper create() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        mapper.enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES);
        return mapper;
    }

    public static ObjectMapper mapper() {
        return MAPPER;
    }

    public static byte[] toBytes(Object value) {
        try {
            return MAPPER.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("cannot encode JSON", e);
        }
    }

    public static String toJson(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("cannot encode JSON", e);
        }
    }

    /** Deterministic encoding (sorted object keys) used for hashing and signing. */
    public static byte[] toCanonicalBytes(Object value) {
        try {
            ObjectMapper canonical = MAPPER.copy();
            canonical.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);
            return canonical.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("cannot encode JSON", e);
        }
    }

    public static <T> T fromBytes(byte[] bytes, Class<T> type) {
        try {
            return MAPPER.readValue(bytes, type);
        } catch (Exception e) {
            throw new IllegalArgumentException("cannot decode JSON as " + type.getSimpleName(), e);
        }
    }

    public static <T> T fromJson(String json, Class<T> type) {
        try {
            return MAPPER.readValue(json, type);
        } catch (Exception e) {
            throw new IllegalArgumentException("cannot decode JSON as " + type.getSimpleName(), e);
        }
    }

    /** Typed object map, for request bodies whose shape the caller validates field by field. */
    @SuppressWarnings("unchecked")
    public static java.util.Map<String, Object> toObjectMap(byte[] bytes) {
        try {
            return MAPPER.readValue(bytes, java.util.Map.class);
        } catch (Exception e) {
            throw new IllegalArgumentException("request body is not a JSON object", e);
        }
    }

    public static JsonNode tree(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("cannot parse JSON", e);
        }
    }
}
