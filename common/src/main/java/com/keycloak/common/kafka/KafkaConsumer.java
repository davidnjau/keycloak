package com.keycloak.common.kafka;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;

@Slf4j
public abstract class KafkaConsumer<T> {

    private final Class<T> clazz;
    private final String mainTopic;
    private final String retryTopic;
    private final String dlqTopic;

    protected KafkaConsumer(Class<T> clazz, String mainTopic) {
        this.clazz = clazz;
        this.mainTopic = mainTopic;
        this.retryTopic = mainTopic + "-retry";
        this.dlqTopic = mainTopic + "-dlq";
    }

    /**
     * Each service overrides this with its own logic.
     */
    protected abstract void handleMessage(T message);

    /**
     * Consume from main topic.
     */
    @KafkaListener(topics = "#{__listener.mainTopic}", groupId = "${spring.kafka.consumer.group-id}")
    public void consumeMain(T message) {
        processMessage(message, mainTopic, retryTopic);
    }

    /**
     * Consume from retry topic.
     */
    @KafkaListener(topics = "#{__listener.retryTopic}", groupId = "${spring.kafka.consumer.group-id}-retry")
    public void consumeRetry(T message) {
        processMessage(message, retryTopic, dlqTopic);
    }

    /**
     * Generic message processor.
     */
    private void processMessage(T message, String currentTopic, String nextTopic) {
        log.info("Received message from topic={}: {}", currentTopic, message);
        try {
            handleMessage(message);
        } catch (Exception ex) {
            log.error("Error processing message from topic={}: {}", currentTopic, message, ex);
            sendToNextTopic(message, nextTopic);
        }
    }

    /**
     * Forward message to retry or DLQ topic.
     */
    private void sendToNextTopic(T message, String targetTopic) {
        try {
            kafkaTemplate().send(targetTopic, message);
            log.warn("Message forwarded to {}", targetTopic);
        } catch (Exception ex) {
            log.error("Failed to forward message to {}: {}", targetTopic, message, ex);
        }
    }

    @Autowired
    private KafkaTemplate<String, Object> kafkaTemplate;
    private KafkaTemplate<String, Object> kafkaTemplate() {
        return kafkaTemplate;
    }

}
