#pragma once
/*
  pattern_cache.h — Persistent Attack Pattern Cache (LittleFS)
*/

#include <Arduino.h>
#include <LittleFS.h>
#include <ArduinoJson.h>
#include "config.h"
#include "packet_monitor.h"

#define PATTERN_FILE "/patterns.json"

struct PatternEntry {
    uint8_t  proto;
    uint8_t  conn_state;
    uint16_t pkt_bin;
    uint16_t byte_bin;

    float pay_ratio;
    float confidence;

    bool is_attack;
    bool active;

    uint32_t hit_count;
    uint32_t total_seen;

    char first_seen[22];
    char last_seen[22];
    char attack_type[16];
};

class PersistentPatternCache {

public:

    PatternEntry entries[CACHE_MAX_SIZE];
    int size = 0;

    uint32_t total_blocked = 0;
    uint32_t total_cached = 0;

    bool fs_ok = false;

    void begin()
    {
        Serial.println("[CACHE] Initialising LittleFS");

        if (!LittleFS.begin(true))
        {
            Serial.println("[CACHE] LittleFS FAILED");
            return;
        }

        fs_ok = true;

        Serial.printf("[CACHE] Flash %u/%u bytes\n",
                      LittleFS.usedBytes(),
                      LittleFS.totalBytes());

        load();
    }

    bool should_block(const FlowFeatures& f, float z)
    {
        PatternEntry c = makePattern(f);

        for (int i = 0; i < CACHE_MAX_SIZE; i++)
        {
            PatternEntry &e = entries[i];

            if (!e.active || !e.is_attack)
                continue;

            float sim = similarity(c, e);

            if (sim >= CACHE_SIM_THRESH)
            {
                e.hit_count++;
                e.total_seen++;

                uptime(e.last_seen, sizeof(e.last_seen));

                total_blocked++;

                if (e.hit_count % 10 == 0)
                    save();

                Serial.printf("[CACHE] BLOCKED sim=%.2f type=%s hits=%lu\n",
                              sim, e.attack_type, e.hit_count);

                blink();

                return true;
            }
        }

        return false;
    }

    void add_attack(const FlowFeatures& f, float conf,
                    const char* atype = "Attack")
    {
        PatternEntry c = makePattern(f, conf, atype);

        for (int i = 0; i < CACHE_MAX_SIZE; i++)
        {
            PatternEntry &e = entries[i];

            if (!e.active) continue;

            if (similarity(c, e) >= CACHE_SIM_THRESH)
            {
                e.confidence = max(e.confidence, conf);
                e.total_seen++;

                uptime(e.last_seen, sizeof(e.last_seen));

                save();

                Serial.println("[CACHE] Pattern refreshed");

                return;
            }
        }

        int slot = freeSlot();

        if (slot < 0)
        {
            slot = evict();
            Serial.println("[CACHE] Cache full → evicted");
        }

        entries[slot] = c;

        size++;
        total_cached++;

        save();

        Serial.printf("[CACHE] Stored pattern type=%s conf=%.2f cache=%d/%d\n",
                      atype, conf, size, CACHE_MAX_SIZE);
    }

    void clear()
    {
        for (int i = 0; i < CACHE_MAX_SIZE; i++)
            entries[i].active = false;

        size = 0;
        total_blocked = 0;
        total_cached = 0;

        if (fs_ok)
            LittleFS.remove(PATTERN_FILE);

        Serial.println("[CACHE] Cleared");
    }

private:

    PatternEntry makePattern(const FlowFeatures& f,
                             float conf = 0,
                             const char* atype = "Unknown")
    {
        PatternEntry e;

        memset(&e, 0, sizeof(e));

        e.proto      = f.proto_tcp ? 0 : (f.proto_udp ? 1 : 2);
        e.conn_state = f.conn_ok ? 0 : (f.conn_s0 ? 1 : 2);

        e.pkt_bin  = bucket(f.packet_rate);
        e.byte_bin = bucket(f.byte_rate / 100);

        e.pay_ratio = roundf(f.payload_ratio * 2.0f) / 2.0f;

        e.is_attack = true;
        e.confidence = conf;

        e.hit_count = 0;
        e.total_seen = 1;

        e.active = true;

        strncpy(e.attack_type, atype, sizeof(e.attack_type) - 1);

        uptime(e.first_seen, sizeof(e.first_seen));
        uptime(e.last_seen, sizeof(e.last_seen));

        return e;
    }

    float similarity(const PatternEntry &a,
                     const PatternEntry &b)
    {
        float s = 0;

        if (a.proto == b.proto) s += 0.25f;
        if (a.conn_state == b.conn_state) s += 0.25f;
        if (a.pkt_bin == b.pkt_bin) s += 0.20f;

        if (abs((int)a.byte_bin - (int)b.byte_bin) <= 1)
            s += 0.20f;

        if (fabsf(a.pay_ratio - b.pay_ratio) <= 0.5f)
            s += 0.10f;

        return s;
    }

    uint16_t bucket(float r)
    {
        if (r < 10) return 0;
        if (r < 50) return 1;
        if (r < 100) return 2;
        if (r < 250) return 3;
        if (r < 500) return 4;
        if (r < 1000) return 5;
        if (r < 2000) return 6;
        if (r < 5000) return 7;
        if (r < 10000) return 8;
        if (r < 20000) return 9;
        return 10;
    }

    int freeSlot()
    {
        for (int i = 0; i < CACHE_MAX_SIZE; i++)
            if (!entries[i].active)
                return i;

        return -1;
    }

    int evict()
    {
        int best = 0;
        uint32_t minHits = UINT32_MAX;

        for (int i = 0; i < CACHE_MAX_SIZE; i++)
        {
            if (entries[i].active &&
                entries[i].hit_count < minHits)
            {
                minHits = entries[i].hit_count;
                best = i;
            }
        }

        entries[best].active = false;
        size--;

        return best;
    }

    void save()
    {
        if (!fs_ok) return;

        StaticJsonDocument<2048> doc;

        JsonArray arr = doc.createNestedArray("patterns");

        for (int i = 0; i < CACHE_MAX_SIZE; i++)
        {
            PatternEntry &e = entries[i];

            if (!e.active || !e.is_attack)
                continue;

            JsonObject o = arr.createNestedObject();

            o["proto"] = e.proto;
            o["conn"]  = e.conn_state;
            o["pkt"]   = e.pkt_bin;
            o["byte"]  = e.byte_bin;
            o["pay"]   = e.pay_ratio;
            o["conf"]  = e.confidence;
            o["hits"]  = e.hit_count;
            o["total"] = e.total_seen;
            o["type"]  = e.attack_type;
            o["first"] = e.first_seen;
            o["last"]  = e.last_seen;
        }

        doc["total_blocked"] = total_blocked;
        doc["total_cached"]  = total_cached;

        File f = LittleFS.open(PATTERN_FILE, "w");

        if (f)
        {
            serializeJson(doc, f);
            f.close();
        }
    }

    void load()
    {
        if (!LittleFS.exists(PATTERN_FILE))
        {
            Serial.println("[CACHE] No saved patterns");
            return;
        }

        File f = LittleFS.open(PATTERN_FILE, "r");

        if (!f) return;

        StaticJsonDocument<2048> doc;

        if (deserializeJson(doc, f))
        {
            f.close();
            return;
        }

        f.close();

        total_blocked = doc["total_blocked"] | 0;
        total_cached  = doc["total_cached"] | 0;

        JsonArray arr = doc["patterns"];

        for (JsonObject o : arr)
        {
            if (size >= CACHE_MAX_SIZE)
                break;

            PatternEntry &e = entries[size];

            e.proto      = o["proto"];
            e.conn_state = o["conn"];
            e.pkt_bin    = o["pkt"];
            e.byte_bin   = o["byte"];
            e.pay_ratio  = o["pay"];
            e.confidence = o["conf"];
            e.hit_count  = o["hits"];
            e.total_seen = o["total"];

            e.is_attack = true;
            e.active = true;

            strncpy(e.attack_type, o["type"] | "Unknown", 15);
            strncpy(e.first_seen,  o["first"] | "unknown", 21);
            strncpy(e.last_seen,   o["last"] | "unknown", 21);

            size++;
        }

        Serial.printf("[CACHE] Loaded %d patterns\n", size);
    }

    void uptime(char* buf, size_t len)
    {
        unsigned long s = millis() / 1000;
        unsigned long m = s / 60;
        unsigned long h = m / 60;

        snprintf(buf, len, "up_%02lu:%02lu:%02lu",
                 h % 24, m % 60, s % 60);
    }

    void blink()
    {
        digitalWrite(LED_ALERT, HIGH);
        delay(40);
        digitalWrite(LED_ALERT, LOW);
    }
};

PersistentPatternCache patternCache;