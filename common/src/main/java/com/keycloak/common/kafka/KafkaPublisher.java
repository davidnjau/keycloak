package com.keycloak.common.kafka;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class KafkaPublisher {

    private final KafkaTemplate<String, Object> kafkaTemplate;

    /**
     * Publishes an event to the given topic.
     *
     * @param topic   Kafka topic name
     * @param key     Optional partitioning key (null allowed)
     * @param payload Event payload (any serializable object)
     */
    public <T> void publish(String topic, String key, T payload) {
        if (payload == null) {
            log.warn("Attempted to publish null payload to topic={}", topic);
            return;
        }

        try {
            kafkaTemplate.send(topic, key, payload)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.error("Failed to publish message to topic={} key={} payload={}", topic, key, payload, ex);
                        } else {
                            log.info("Successfully published message to topic={} partition={} offset={}",
                                    topic,
                                    result.getRecordMetadata().partition(),
                                    result.getRecordMetadata().offset());
                        }
                    });
        } catch (Exception ex) {
            log.error("Exception while publishing to topic={} key={} payload={}", topic, key, payload, ex);
        }
    }

    /**
     * Overloaded method without key (round-robin partitioning).
     */
    public <T> void publish(String topic, T payload) {
        publish(topic, null, payload);
    }

}
