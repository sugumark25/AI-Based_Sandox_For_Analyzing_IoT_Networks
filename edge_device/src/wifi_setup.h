#pragma once
/*
  wifi_setup.h — WiFi Connection Manager
  ======================================
  Handles WiFi connection and auto reconnection.

  ESP32 connects to existing router using STA mode.

  NOTE:
  Packet sniffer should start only AFTER WiFi connects
  because it requires the correct channel information.
*/

#include <WiFi.h>
#include "config.h"

bool wifiConnected = false;
unsigned long lastWifiRetry = 0;


// ─────────────────────────────────────────
// Initial WiFi connection (blocking)
// Call once in setup()
// ─────────────────────────────────────────
void connectWiFi(unsigned long timeoutMs = 15000UL)
{
    Serial.printf("[WIFI] Connecting to '%s'", WIFI_SSID);

    WiFi.mode(WIFI_STA);
    WiFi.persistent(false);        // prevent flash wear
    WiFi.setAutoReconnect(true);   // auto reconnect

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

    unsigned long start = millis();

    while (WiFi.status() != WL_CONNECTED &&
           (millis() - start) < timeoutMs)
    {
        Serial.print(".");
        delay(500);
    }

    if (WiFi.status() == WL_CONNECTED)
    {
        wifiConnected = true;

        Serial.println(" OK");

        Serial.printf("[WIFI] IP      : %s\n",
                      WiFi.localIP().toString().c_str());

        Serial.printf("[WIFI] Gateway : %s\n",
                      WiFi.gatewayIP().toString().c_str());

        Serial.printf("[WIFI] RSSI    : %d dBm\n",
                      WiFi.RSSI());
    }
    else
    {
        wifiConnected = false;

        Serial.println(" FAILED");
        Serial.println("[WIFI] Check WIFI_SSID and WIFI_PASSWORD in config.h");
    }

    lastWifiRetry = millis();
}


// ─────────────────────────────────────────
// Maintain connection (non-blocking)
// Call inside loop()
// ─────────────────────────────────────────
void maintainWiFi()
{
    if (WiFi.status() == WL_CONNECTED)
    {
        if (!wifiConnected)
        {
            wifiConnected = true;

            Serial.printf("[WIFI] Reconnected: %s\n",
                          WiFi.localIP().toString().c_str());
        }

        return;
    }

    wifiConnected = false;

    unsigned long now = millis();

    if (now - lastWifiRetry < 5000UL)
        return;

    lastWifiRetry = now;

    Serial.println("[WIFI] Attempting reconnect...");

    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
}