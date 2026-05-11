#pragma once

#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include "config.h"
#include "packet_monitor.h"
#include "wifi_setup.h"
#include "sensor_reader.h"

// ── Topics ─────────────────────────────────────────────
char TOPIC_FLOW[64];
char TOPIC_ALERT[64];
char TOPIC_SENSOR[64];
char TOPIC_STATUS[64];
char TOPIC_COMMANDS[64];

// ── State ──────────────────────────────────────────────
bool          newResult      = false;
bool          resultIsAttack = false;
float         resultConf     = 0.0f;
float         resultLatency  = 0.0f;
unsigned long lastMqttRetry  = 0;
bool          newCommand     = false;
char          lastCommandMsg[512] = {0};

// ── MQTT Client ────────────────────────────────────────
WiFiClient   wifiClient;
PubSubClient mqttClient(wifiClient);

// ── Callback ───────────────────────────────────────────
void mqttCallback(char* topic, byte* payload, unsigned int len)
{
    char msg[512];
    int n = min(len, sizeof(msg) - 1);

    memcpy(msg, payload, n);
    msg[n] = '\0';

    StaticJsonDocument<512> doc;

    if (deserializeJson(doc, msg) != DeserializationError::Ok) {
        Serial.println("[MQTT] Invalid JSON");
        return;
    }

    if (strstr(topic, "alerts"))
    {
        resultIsAttack = doc["is_attack"];
        resultConf     = doc["confidence"];
        resultLatency  = doc["latency_ms"];
        newResult      = true;

        Serial.printf("[MQTT] ALERT → %s (%.2f)\n",
                      resultIsAttack ? "ATTACK" : "NORMAL",
                      resultConf);
    }
    
    if (strstr(topic, "commands"))
    {
        Serial.printf("[MQTT] COMMAND received: %s\n", msg);
        newCommand = true;
        strncpy(lastCommandMsg, msg, sizeof(lastCommandMsg) - 1);
        
        // Block command will be processed in main loop via parseBlockCommand()
        // See block_command.h for execution logic
    }
}

// ── Setup MQTT ─────────────────────────────────────────
void setupMQTT()
{
    snprintf(TOPIC_FLOW, sizeof(TOPIC_FLOW),     "iot/flows/%s", DEVICE_ID);
    snprintf(TOPIC_ALERT, sizeof(TOPIC_ALERT),   "iot/alerts/%s", DEVICE_ID);
    snprintf(TOPIC_SENSOR, sizeof(TOPIC_SENSOR), "iot/sensors/%s", DEVICE_ID);
    snprintf(TOPIC_STATUS, sizeof(TOPIC_STATUS), "iot/status/%s", DEVICE_ID);
    snprintf(TOPIC_COMMANDS, sizeof(TOPIC_COMMANDS), "iot/commands/%s", DEVICE_ID);

    mqttClient.setServer(MQTT_BROKER_HOST, MQTT_BROKER_PORT);
    mqttClient.setCallback(mqttCallback);

    Serial.println("========== MQTT CONFIG ==========");
    Serial.printf("Broker: %s:%d\n", MQTT_BROKER_HOST, MQTT_BROKER_PORT);
    Serial.println("=================================");
}

// ── Connect ────────────────────────────────────────────
bool mqttConnect()
{
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("[MQTT] WiFi not connected");
        return false;
    }

    char clientId[40];
    sprintf(clientId, "ESP32-%lu", millis());

    Serial.print("[MQTT] Connecting... ");

    bool ok = mqttClient.connect(clientId);

    if (ok)
    {
        Serial.println("✅ CONNECTED");

        mqttClient.subscribe(TOPIC_ALERT);
        mqttClient.subscribe(TOPIC_COMMANDS);  // Subscribe to blocking commands
        mqttClient.publish(TOPIC_STATUS, "{\"status\":\"online\"}");
    }
    else
    {
        Serial.printf("❌ FAILED (rc=%d)\n", mqttClient.state());

        Serial.println("👉 rc = -2 means:");
        Serial.println("   - Wrong IP");
        Serial.println("   - Broker not reachable");
        Serial.println("   - Firewall blocking");
    }

    return ok;
}

// ── Maintain ───────────────────────────────────────────
void maintainMQTT()
{
    if (WiFi.status() != WL_CONNECTED) return;

    if (mqttClient.connected()) {
        mqttClient.loop();
        return;
    }

    if (millis() - lastMqttRetry > 5000)
    {
        lastMqttRetry = millis();
        mqttConnect();
    }
}

// ── Publish ────────────────────────────────────────────
bool mqttPublishFlow(const FlowFeatures& f, float z)
{
    if (!mqttClient.connected())
        return false;

    StaticJsonDocument<512> doc;

    doc["device_id"] = DEVICE_ID;
    doc["type"] = "flow";

    doc["duration"]  = f.duration;
    doc["src_bytes"] = f.src_bytes;
    doc["dst_bytes"] = f.dst_bytes;

    doc["src_pkts"]  = f.src_pkts;
    doc["dst_pkts"]  = f.dst_pkts;

    doc["proto"] =
        f.proto_tcp ? "tcp" :
        f.proto_udp ? "udp" : "icmp";

    doc["anomaly_score"] = z;
    doc["ts"] = millis();

    sensorAttachToJson(doc);

    char payload[512];
    serializeJson(doc, payload);

    bool ok = mqttClient.publish(TOPIC_FLOW, payload);

    Serial.printf("[MQTT] Sent → %s\n", ok ? "OK" : "FAIL");

    return ok;
}