#pragma once
#ifndef TINYML_INFERENCE_H
#define TINYML_INFERENCE_H

#include <Arduino.h>
#include <cmath>
#include <cstring>
#include "scaler.h"
#include "tinyml_weights.h"
#include "packet_monitor.h"

struct EdgeResult {
    bool  is_attack;
    float confidence;
    float probability;
    float inference_ms;
    bool  valid;
};

inline void flowToArray(const FlowFeatures& f, float out[NN_INPUT_SIZE]) {
    out[0]=f.duration;           out[1]=f.src_bytes;
    out[2]=f.dst_bytes;          out[3]=f.src_pkts;
    out[4]=f.dst_pkts;           out[5]=f.packet_rate;
    out[6]=f.byte_rate;          out[7]=f.bytes_per_pkt;
    out[8]=f.payload_ratio;      out[9]=f.proto_tcp;
    out[10]=f.proto_udp;         out[11]=f.proto_icmp;
    out[12]=f.conn_ok;           out[13]=f.conn_s0;
    out[14]=f.conn_rej;          out[15]=f.jitter;
    out[16]=f.flow_weight;       out[17]=f.magnitude;
    out[18]=f.variance;          out[19]=f.logged_in;
    out[20]=f.num_failed_logins; out[21]=f.srv_count;
}

inline float _relu(float x) {
    return x > 0.0f ? x : 0.0f;
}

inline float _sigmoid(float x) {
    if (x >  20.0f) return 1.0f;
    if (x < -20.0f) return 0.0f;
    return 1.0f / (1.0f + expf(-x));
}

class EdgeInference {
public:
    bool ready = false;

    // ── Initialize ────────────────────────────────────────────
    bool begin() {
        ready = true;
        Serial.println("[TINYML] Neural network loaded");
        Serial.printf("[TINYML]    Architecture : %d->%d->%d->%d\n",
                      NN_INPUT_SIZE, NN_H1_SIZE,
                      NN_H2_SIZE, NN_OUTPUT_SIZE);
        Serial.printf("[TINYML]    Threshold    : %.2f\n", NN_THRESHOLD);
        Serial.printf("[TINYML]    Precision    : 0.9073\n");
        Serial.printf("[TINYML]    Recall       : 1.0000\n");
        Serial.printf("[TINYML]    F1 Score     : 0.9514\n");
        return true;
    }

    // ── Forward pass ──────────────────────────────────────────
    EdgeResult predict(const FlowFeatures& f) {
        EdgeResult r = {false, 0.0f, 0.0f, 0.0f, false};

        // Step 1 — flatten struct to array
        float feat[NN_INPUT_SIZE];
        flowToArray(f, feat);

        // Step 2 — normalize using trained scaler
        for (int i = 0; i < NN_INPUT_SIZE; i++) {
            float s = (NN_SCALE[i] > 1e-9f) ? NN_SCALE[i] : 1e-9f;
            float n = (feat[i] - NN_MEAN[i]) / s;
            if      (n >  10.0f)       n =  10.0f;
            else if (n < -10.0f)       n = -10.0f;
            if (isnan(n) || isinf(n))  n =  0.0f;
            feat[i] = n;
        }

        unsigned long t0 = micros();

        // Step 3 — Layer 1: 22 → 32 ReLU
        float h1[NN_H1_SIZE];
        for (int j = 0; j < NN_H1_SIZE; j++) {
            float s = NN_B1[j];
            for (int i = 0; i < NN_INPUT_SIZE; i++)
                s += feat[i] * NN_W1[j * NN_INPUT_SIZE + i];
            h1[j] = _relu(s);
        }

        // Step 4 — Layer 2: 32 → 16 ReLU
        float h2[NN_H2_SIZE];
        for (int j = 0; j < NN_H2_SIZE; j++) {
            float s = NN_B2[j];
            for (int i = 0; i < NN_H1_SIZE; i++)
                s += h1[i] * NN_W2[j * NN_H1_SIZE + i];
            h2[j] = _relu(s);
        }

        // Step 5 — Layer 3: 16 → 1 Sigmoid
        float out = NN_B3[0];
        for (int i = 0; i < NN_H2_SIZE; i++)
            out += h2[i] * NN_W3[i];
        out = _sigmoid(out);

        r.inference_ms = (micros() - t0) / 1000.0f;
        r.probability  = out;
        r.confidence   = out;            // real NN probability 0.0-1.0
        r.is_attack    = (out >= NN_THRESHOLD);
        r.valid        = true;
        return r;
    }

    bool  isReady() const { return ready; }

    void diagnostics() const {
        Serial.println("------ TinyML Diagnostics ------");
        Serial.println("  Mode      : Hardcoded weights");
        Serial.println("  Status    : READY");
        Serial.printf ("  Arch      : %d->%d->%d->%d\n",
                       NN_INPUT_SIZE, NN_H1_SIZE,
                       NN_H2_SIZE, NN_OUTPUT_SIZE);
        Serial.printf ("  Threshold : %.2f\n", NN_THRESHOLD);
        Serial.println("  Trained   : 680 normal + 75 attack");
        Serial.println("  Precision : 0.9073");
        Serial.println("  Recall    : 1.0000");
        Serial.println("  F1        : 0.9514");
        Serial.println("--------------------------------");
    }
};

#endif // TINYML_INFERENCE_H