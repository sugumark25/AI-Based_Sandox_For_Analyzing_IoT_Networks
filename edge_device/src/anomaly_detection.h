#pragma once
/*
  anomaly_detection.h — HTTP Fallback to Flask Backend (Legacy)
  ===============================================================
  Used when MQTT is unavailable. Sends flow directly to
  /api/predict endpoint via HTTP POST and reads ML result.
  Blocking call — waits up to 3 seconds for response.
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "config.h"
#include "packet_monitor.h"
#include "wifi_setup.h"
#include "sensor_reader.h"

bool sendToBackend(const FlowFeatures& f, float z)
{
    // Ensure WiFi connection
    if (WiFi.status() != WL_CONNECTED || !wifiConnected) {
        Serial.println("[HTTP] WiFi not connected");
        return false;
    }

    HTTPClient http;

    char url[128];
    snprintf(url, sizeof(url), "http://%s:%d%s",
             BACKEND_HOST, BACKEND_PORT, PREDICT_PATH);

    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    http.setTimeout(3000);

    // JSON document
    StaticJsonDocument<512> doc;

    doc["device_id"]         = DEVICE_ID;
    doc["duration"]          = f.duration;
    doc["src_bytes"]         = f.src_bytes;
    doc["dst_bytes"]         = f.dst_bytes;
    doc["src_pkts"]          = f.src_pkts;
    doc["dst_pkts"]          = f.dst_pkts;

    doc["proto"] = f.proto_tcp ? "tcp" :
                   f.proto_udp ? "udp" : "icmp";

    doc["conn_state"] = f.conn_ok ? "SF" :
                        f.conn_s0 ? "S0" : "REJ";

    doc["logged_in"]         = f.logged_in;
    doc["num_failed_logins"] = f.num_failed_logins;
    doc["srv_count"]         = f.srv_count;
    doc["anomaly_score"]     = z;

    // Attach sensor data
    sensorAttachToJson(doc);

    char body[512];
    serializeJson(doc, body, sizeof(body));

    int code = http.POST((uint8_t*)body, strlen(body));

    if (code == HTTP_CODE_OK)
    {
        String resp = http.getString();

        StaticJsonDocument<256> res;
        DeserializationError err = deserializeJson(res, resp);

        if (!err)
        {
            bool  atk = res["is_attack"];
            float con = res["confidence"];
            float lat = res["latency_ms"];

            Serial.printf("[HTTP] %s  conf=%.2f  %.1fms\n",
                          atk ? "ATTACK" : "normal",
                          con, lat);

            // Share result with main system
            extern bool  newResult;
            extern bool  resultIsAttack;
            extern float resultConf;
            extern float resultLatency;

            newResult      = true;
            resultIsAttack = atk;
            resultConf     = con;
            resultLatency  = lat;

            if (atk)
            {
                for (int i = 0; i < 4; i++)
                {
                    digitalWrite(LED_ALERT, HIGH);
                    delay(80);
                    digitalWrite(LED_ALERT, LOW);
                    delay(80);
                }
            }
        }
        else
        {
            Serial.println("[HTTP] JSON parse error");
        }

        http.end();
        return true;
    }

    Serial.printf("[HTTP] Error %d\n", code);
    http.end();
    return false;
}