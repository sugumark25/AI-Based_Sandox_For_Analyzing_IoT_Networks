#pragma once
/*
  packet_monitor.h — Real WiFi Packet Capture for ESP32-E
*/

#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cmath>
#include "config.h"

// ── Mutex for shared variables ─────────────────────────────
portMUX_TYPE snifferMux = portMUX_INITIALIZER_UNLOCKED;

// ── Rolling window for Z-score ─────────────────────────────
struct RollingWindow {
    float buf[WINDOW_SIZE];
    int idx = 0;
    int count = 0;

    void push(float v) {
        buf[idx] = v;
        idx = (idx + 1) % WINDOW_SIZE;
        if (count < WINDOW_SIZE) count++;
    }

    float mean() const {
        if (count == 0) return 0.0f;
        float s = 0;
        for (int i = 0; i < count; i++) s += buf[i];
        return s / count;
    }

    float stddev() const {
        if (count < 2) return 1.0f;
        float m = mean(), v = 0;
        for (int i = 0; i < count; i++)
            v += (buf[i] - m) * (buf[i] - m);
        return sqrtf(v / count) + 1e-6f;
    }

    float zscore(float v) const {
        return fabsf((v - mean()) / stddev());
    }
};

// ── Feature structure (22 features) ────────────────────────
struct FlowFeatures {
    float duration;
    float src_bytes;
    float dst_bytes;
    float src_pkts;
    float dst_pkts;

    float packet_rate;
    float byte_rate;
    float bytes_per_pkt;
    float payload_ratio;

    bool proto_tcp;
    bool proto_udp;
    bool proto_icmp;

    bool conn_ok;
    bool conn_s0;
    bool conn_rej;

    float jitter;
    float flow_weight;
    float magnitude;
    float variance;

    float logged_in;
    float num_failed_logins;
    float srv_count;
};

// ── WiFi MAC header ────────────────────────────────────────
typedef struct {
    uint8_t  frame_ctrl[2];
    uint16_t duration_id;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} ieee80211_mac_hdr_t;

// ── Shared counters ────────────────────────────────────────
volatile uint32_t g_tx_pkts  = 0;
volatile uint32_t g_rx_pkts  = 0;
volatile uint32_t g_tx_bytes = 0;
volatile uint32_t g_rx_bytes = 0;
volatile uint32_t g_mgmt     = 0;
volatile uint32_t g_data     = 0;
volatile uint32_t g_rssi_sum = 0;
volatile uint32_t g_rssi_cnt = 0;
volatile uint32_t g_jit_sum  = 0;
volatile uint32_t g_last_us  = 0;

uint8_t g_own_mac[6];

// ── Sniffer callback ───────────────────────────────────────
// Counts ALL packets on the channel — not just ESP32's own traffic.
// This allows detecting high packet rates from any device on network.
void IRAM_ATTR sniffer_cb(void* buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t* p = (wifi_promiscuous_pkt_t*)buf;

    uint16_t len  = p->rx_ctrl.sig_len;
    int8_t   rssi = p->rx_ctrl.rssi;
    uint32_t now  = micros();

    portENTER_CRITICAL_ISR(&snifferMux);

    // Jitter tracking
    if (g_last_us != 0)
        g_jit_sum += (now - g_last_us);
    g_last_us = now;

    // RSSI tracking
    g_rssi_sum += abs(rssi);
    g_rssi_cnt++;

    if (type == WIFI_PKT_MGMT) {
        g_mgmt++;
        portEXIT_CRITICAL_ISR(&snifferMux);
        return;
    }

    if (type != WIFI_PKT_DATA) {
        portEXIT_CRITICAL_ISR(&snifferMux);
        return;
    }

    g_data++;

    // ── Count ALL data packets on channel ──────────────────
    // Previously only counted ESP32's own TX/RX which gave pkt=0
    // when flood traffic was destined for other IPs.
    // Now we count everything — any traffic spike = anomaly.
    if (len >= sizeof(ieee80211_mac_hdr_t)) {
        const ieee80211_mac_hdr_t* h =
            (const ieee80211_mac_hdr_t*)p->payload;

        bool is_own_tx = memcmp(h->addr2, g_own_mac, 6) == 0;
        bool is_own_rx = memcmp(h->addr1, g_own_mac, 6) == 0;

        if (is_own_tx) {
            // ESP32 sending — count as TX
            g_tx_pkts++;
            g_tx_bytes += len;
        } else if (is_own_rx) {
            // ESP32 receiving — count as RX
            g_rx_pkts++;
            g_rx_bytes += len;
        } else {
            // Third-party traffic on same channel — count as RX
            // This is what flood.py generates
            g_rx_pkts++;
            g_rx_bytes += len;
        }
    }

    portEXIT_CRITICAL_ISR(&snifferMux);
}

// ── Flow monitor class ─────────────────────────────────────
class FlowMonitor {

public:

    RollingWindow pkt_win;
    RollingWindow byte_win;

    unsigned long t0 = 0;

    void reset()
    {
        portENTER_CRITICAL(&snifferMux);
        g_tx_pkts = g_rx_pkts = 0;
        g_tx_bytes = g_rx_bytes = 0;
        g_mgmt = g_data = 0;
        g_rssi_sum = g_rssi_cnt = 0;
        g_jit_sum = g_last_us = 0;
        portEXIT_CRITICAL(&snifferMux);
        t0 = millis();
    }

    FlowFeatures extract()
    {
        portENTER_CRITICAL(&snifferMux);
        uint32_t txp  = g_tx_pkts;
        uint32_t rxp  = g_rx_pkts;
        uint32_t txb  = g_tx_bytes;
        uint32_t rxb  = g_rx_bytes;
        uint32_t mgmt = g_mgmt;
        uint32_t rs   = g_rssi_sum;
        uint32_t rc   = g_rssi_cnt;
        uint32_t js   = g_jit_sum;
        portEXIT_CRITICAL(&snifferMux);

        FlowFeatures f;

        float dur = max((millis() - t0) / 1000.0f, 0.001f);
        float tp  = txp + rxp;
        float tb  = txb + rxb;

        f.duration      = dur;
        f.src_bytes     = txb;
        f.dst_bytes     = rxb;
        f.src_pkts      = txp;
        f.dst_pkts      = rxp;
        f.packet_rate   = tp / dur;
        f.byte_rate     = tb / dur;
        f.bytes_per_pkt = tp > 0 ? tb / tp : 0;
        f.payload_ratio = (txb > 0) ? rxb / txb : 0;

        f.proto_tcp  = true;
        f.proto_udp  = false;
        f.proto_icmp = false;

        f.conn_ok  = (rxp > 0);
        f.conn_s0  = (txp > 50 && rxp == 0);
        f.conn_rej = (f.packet_rate > 500);

        float avg_rssi   = rc > 0 ? -(float)rs / rc : -70;
        float avg_jitter = tp > 1 ? (float)js / tp / 1000.0f : 0;

        f.jitter      = avg_jitter;
        f.flow_weight = avg_rssi;
        f.magnitude   = sqrtf(f.src_bytes * f.src_bytes +
                               f.dst_bytes * f.dst_bytes);
        f.variance    = fabsf(f.byte_rate - f.bytes_per_pkt);

        f.logged_in         = 1;
        f.num_failed_logins = 0;
        f.srv_count         = mgmt;

        pkt_win.push(f.packet_rate);
        byte_win.push(f.byte_rate);

        return f;
    }

    float anomalyScore(const FlowFeatures& f)
    {
        return (pkt_win.zscore(f.packet_rate) +
                byte_win.zscore(f.byte_rate)) / 2.0f;
    }
};

// ── Start sniffer ──────────────────────────────────────────
inline bool startSniffer()
{
    esp_wifi_get_mac(WIFI_IF_STA, g_own_mac);

    Serial.printf(
        "[SNIFFER] MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
        g_own_mac[0], g_own_mac[1], g_own_mac[2],
        g_own_mac[3], g_own_mac[4], g_own_mac[5]);

    wifi_promiscuous_filter_t filt;
    filt.filter_mask = WIFI_PROMIS_FILTER_MASK_ALL;

    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(sniffer_cb);

    esp_err_t err = esp_wifi_set_promiscuous(true);

    if (err != ESP_OK) {
        Serial.printf("[SNIFFER] FAILED %d\n", err);
        return false;
    }

    uint8_t ch;
    wifi_second_chan_t sc;
    esp_wifi_get_channel(&ch, &sc);
    Serial.printf("[SNIFFER] Running on channel %d\n", ch);

    return true;
}

// ── Stop sniffer ───────────────────────────────────────────
inline void stopSniffer()
{
    esp_wifi_set_promiscuous(false);
    Serial.println("[SNIFFER] stopped");
}