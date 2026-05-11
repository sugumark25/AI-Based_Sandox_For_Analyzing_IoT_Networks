#pragma once
#ifndef EDGE_MIRROR_H
#define EDGE_MIRROR_H

#include <Arduino.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>
#include "config.h"
#include "packet_monitor.h"
#include "wifi_setup.h"
#include "tinyml_inference.h"

struct MirrorResult {
    bool  sent;
    bool  used_mqtt;
    int   http_code;
    float latency_ms;
    char  error[48];
};

extern PubSubClient mqttClient;
extern bool         wifiConnected;

class EdgeMirror {

public:

    uint32_t total_flows     = 0;
    uint32_t flows_normal    = 0;
    uint32_t flows_attack    = 0;
    uint32_t send_failures   = 0;
    uint32_t mqtt_sent       = 0;
    uint32_t http_sent       = 0;
    float    bandwidth_saved_pct = 0.0f;

    MirrorResult mirror(const FlowFeatures& f,
                        const EdgeResult&   result,
                        float               z_score)
    {
        MirrorResult mr = {false, false, 0, 0.0f, "not sent"};
        total_flows++;

        unsigned long t_start = millis();

        float feat[SCALER_N_FEATURES];
        flowToArray(f, feat);

        bool sent = false;

        // ── Try MQTT ──────────────────────────────────────────────
        if (_mqttAvailable()) {
            sent = _sendMQTT(feat, z_score, result);
            if (sent) {
                mr.used_mqtt = true;
                mqtt_sent++;
            }
        }

        // ── HTTP fallback ─────────────────────────────────────────
        if (!sent && _httpAvailable()) {
            int code = _sendHTTP(feat, z_score, result);
            sent         = (code == 200);
            mr.http_code = code;
            if (sent) http_sent++;
        }

        mr.latency_ms = (float)(millis() - t_start);
        mr.sent       = sent;

        if (sent) {
            if (result.is_attack) flows_attack++;
            else                  flows_normal++;
            snprintf(mr.error, sizeof(mr.error), "ok");
        } else {
            send_failures++;
            snprintf(mr.error, sizeof(mr.error), "all transports failed");
        }

        _updateBandwidthStat();
        return mr;
    }

    void printStats() const {
        Serial.println("\n------ Edge Mirror Stats ------");
        Serial.printf("  Total flows     : %u\n", total_flows);
        Serial.printf("  Attack mirrored : %u\n", flows_attack);
        Serial.printf("  Normal mirrored : %u\n", flows_normal);
        Serial.printf("  Send failures   : %u\n", send_failures);
        Serial.printf("  MQTT sent       : %u\n", mqtt_sent);
        Serial.printf("  HTTP sent       : %u\n", http_sent);
        Serial.println("-------------------------------\n");
    }

private:

    bool _buildPayload(char*             buf,
                       size_t            buf_size,
                       const float       feat[SCALER_N_FEATURES],
                       float             z_score,
                       const EdgeResult& result)
    {
        JsonDocument doc;

        doc["device_id"]       = DEVICE_ID;
        doc["z_score"]         = z_score;
        doc["edge_confidence"] = result.confidence;
        doc["edge_decision"]   = result.is_attack;
        doc["timestamp"]       = millis();

        JsonArray arr = doc["features"].to<JsonArray>();
        for (int i = 0; i < SCALER_N_FEATURES; i++)
            arr.add(feat[i]);

        size_t written = serializeJson(doc, buf, buf_size);
        return (written > 0 && written < buf_size);
    }

    bool _sendMQTT(const float       feat[SCALER_N_FEATURES],
                   float             z_score,
                   const EdgeResult& result)
    {
        // ── Increase buffer to handle 226 byte payloads ───────────
        mqttClient.setBufferSize(512);

        char payload[512];
        if (!_buildPayload(payload, sizeof(payload), feat, z_score, result))
            return false;

        char topic[72];
        if (result.is_attack)
            snprintf(topic, sizeof(topic), "iot/edge/attacks/%s", DEVICE_ID);
        else
            snprintf(topic, sizeof(topic), "iot/edge/normal/%s",  DEVICE_ID);

        // ── Retry once before giving up ───────────────────────────
        bool ok = mqttClient.publish(topic, payload, false);
        if (!ok) {
            delay(10);
            ok = mqttClient.publish(topic, payload, false);
        }

        Serial.printf("[MIRROR] MQTT -> %s  %s  (%d bytes)\n",
                      topic, ok ? "OK" : "FAIL", strlen(payload));
        return ok;
    }

    int _sendHTTP(const float       feat[SCALER_N_FEATURES],
                  float             z_score,
                  const EdgeResult& result)
    {
        char payload[512];
        if (!_buildPayload(payload, sizeof(payload), feat, z_score, result))
            return -1;

        char url[128];
        snprintf(url, sizeof(url), "http://%s:%d%s",
                 BACKEND_HOST, BACKEND_PORT, PREDICT_PATH);

        HTTPClient http;
        http.begin(url);
        http.addHeader("Content-Type", "application/json");
        http.setTimeout(3000);

        int code = http.POST((uint8_t*)payload, strlen(payload));

        Serial.printf("[MIRROR] HTTP -> %s  code=%d  (%d bytes)\n",
                      url, code, strlen(payload));
        http.end();
        return code;
    }

    bool _mqttAvailable() const {
        return (WiFi.status() == WL_CONNECTED) && mqttClient.connected();
    }

    bool _httpAvailable() const {
        return (WiFi.status() == WL_CONNECTED) && wifiConnected;
    }

    void _updateBandwidthStat() {
        bandwidth_saved_pct = 0.0f;
    }
};

#endif // EDGE_MIRROR_H