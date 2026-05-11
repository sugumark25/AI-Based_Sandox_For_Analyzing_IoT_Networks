#pragma once
/*
  sensor_reader.h — DHT11/DHT22 Temperature + Humidity
  ======================================================

  Reads DHT sensor every 30 seconds.
  Attaches reading to every flow MQTT message automatically.
  Publishes standalone sensor reading to iot/sensors/<id>.

  Wiring:
    DHT DATA → GPIO 15 (set DHT_PIN in config.h)
    VCC      → 3.3V
    GND      → GND
    Optional: 10kΩ pull-up between DATA and 3.3V
*/

#include <Arduino.h>
#include <DHT.h>
#include <ArduinoJson.h>
#include <PubSubClient.h>     // ✅ REQUIRED
#include "config.h"

DHT dht(DHT_PIN, DHT_TYPE);

struct SensorReading {
    float temperature_c;
    float temperature_f;
    float humidity;
    float heat_index_c;
    float heat_index_f;
    bool  valid;
    char  comfort[12];
    char  ts_str[24];
};

SensorReading latestReading = {0,0,0,0,0,false,"UNKNOWN","-"};

unsigned long lastSensorRead = 0;
uint32_t sensorReadCount = 0;
uint32_t sensorFailCount = 0;


// ─────────────────────────────────────────
// Comfort classification
// ─────────────────────────────────────────
inline void _setComfort(SensorReading& r) {

    float t = r.temperature_c;
    float h = r.humidity;

    if      (t > 35 && h > 70) strcpy(r.comfort, "HOT_HUMID");
    else if (t > 35)           strcpy(r.comfort, "HOT");
    else if (t > 28 && h > 70) strcpy(r.comfort, "HUMID");
    else if (t > 28)           strcpy(r.comfort, "WARM");
    else if (t < 10)           strcpy(r.comfort, "COLD");
    else if (h < 30)           strcpy(r.comfort, "DRY");
    else                       strcpy(r.comfort, "NORMAL");
}


// ─────────────────────────────────────────
// Create uptime timestamp
// ─────────────────────────────────────────
inline void _uptimeStr(char* buf, size_t len) {

    unsigned long s = millis() / 1000;
    unsigned long m = s / 60;
    unsigned long h = m / 60;

    snprintf(buf, len, "uptime_%02lu:%02lu:%02lu",
             h % 24, m % 60, s % 60);
}


// ─────────────────────────────────────────
// Sensor Init
// ─────────────────────────────────────────
inline void sensorBegin() {

    dht.begin();

    delay(2000);

    Serial.printf("[SENSOR] DHT%d on GPIO%d  every %lus\n",
                  DHT_TYPE == DHT11 ? 11 : 22,
                  DHT_PIN,
                  SENSOR_INTERVAL_MS / 1000UL);
}


// ─────────────────────────────────────────
// Sensor Tick (call in loop)
// ─────────────────────────────────────────
inline bool sensorTick() {

    if (millis() - lastSensorRead < SENSOR_INTERVAL_MS)
        return false;

    lastSensorRead = millis();

    float humidity = dht.readHumidity();
    float tempC = dht.readTemperature();
    float tempF = dht.readTemperature(true);

    if (isnan(humidity) || isnan(tempC) || isnan(tempF) ||
        tempC < -10 || tempC > 80 ||
        humidity < 0 || humidity > 100) {

        sensorFailCount++;
        latestReading.valid = false;

        Serial.printf("[SENSOR] Read FAILED (fail=%lu ok=%lu)\n",
                      sensorFailCount, sensorReadCount);

        return false;
    }

    latestReading.temperature_c = tempC;
    latestReading.temperature_f = tempF;
    latestReading.humidity = humidity;

    latestReading.heat_index_c = dht.computeHeatIndex(tempC, humidity, false);
    latestReading.heat_index_f = dht.computeHeatIndex(tempF, humidity, true);

    latestReading.valid = true;

    _setComfort(latestReading);
    _uptimeStr(latestReading.ts_str, sizeof(latestReading.ts_str));

    sensorReadCount++;

    Serial.printf(
        "[SENSOR] Temp=%.1f°C  Hum=%.1f%%  HeatIdx=%.1f°C  %s  (#%lu)\n",
        tempC,
        humidity,
        latestReading.heat_index_c,
        latestReading.comfort,
        sensorReadCount
    );

    return true;
}


// ─────────────────────────────────────────
// Attach sensor values to JSON message
// ─────────────────────────────────────────
inline void sensorAttachToJson(JsonDocument& doc) {

    if (!latestReading.valid) {
        doc["sensor_ok"] = false;
        return;
    }

    doc["sensor_ok"] = true;
    doc["temp_c"] = latestReading.temperature_c;
    doc["temp_f"] = latestReading.temperature_f;
    doc["humidity"] = latestReading.humidity;
    doc["heat_index_c"] = latestReading.heat_index_c;
    doc["heat_index_f"] = latestReading.heat_index_f;
    doc["comfort"] = latestReading.comfort;
    doc["sensor_ts"] = latestReading.ts_str;
}


// ─────────────────────────────────────────
// Publish sensor MQTT message
// ─────────────────────────────────────────
inline bool sensorPublishMQTT(PubSubClient& client) {

    if (!client.connected()) return false;

    JsonDocument doc;

    doc["device_id"] = DEVICE_ID;
    doc["type"] = "sensor";
    doc["sensor_ok"] = latestReading.valid;

    if (latestReading.valid) {

        doc["temp_c"] = latestReading.temperature_c;
        doc["temp_f"] = latestReading.temperature_f;
        doc["humidity"] = latestReading.humidity;
        doc["heat_index_c"] = latestReading.heat_index_c;
        doc["heat_index_f"] = latestReading.heat_index_f;
        doc["comfort"] = latestReading.comfort;
    }

    doc["read_count"] = sensorReadCount;
    doc["fail_count"] = sensorFailCount;
    doc["ts"] = millis();

    char topic[64];
    char payload[400];

    snprintf(topic, sizeof(topic), "iot/sensors/%s", DEVICE_ID);

    serializeJson(doc, payload, sizeof(payload));

    bool ok = client.publish(topic, payload);

    Serial.printf("[SENSOR] MQTT → %s  %s\n",
                  topic,
                  ok ? "OK" : "FAILED");

    return ok;
}