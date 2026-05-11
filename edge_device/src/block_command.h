#pragma once
/*
  block_command.h — Handle blocking commands from backend
  
  Receives blocking commands via MQTT topic:
    iot/commands/{device_id}
  
  Executes blocking logic based on command action:
    - block_ip: Drop packets from specified IP
    - block_proto: Drop packets for specific protocol
    - block_port: Drop packets to specific port
    - drop_traffic: General traffic dropping
*/

#include <Arduino.h>
#include <ArduinoJson.h>
#include "config.h"
#include "packet_monitor.h"

// ── Command structure ─────────────────────────────────
struct BlockCommand {
    char cmd_id[64];
    char action[32];      // "block_ip", "block_port", "block_proto", etc.
    char target[64];      // IP address, port number, or protocol name
    char reason[128];     // "DDoS", "PortScan", etc.
    unsigned long created_at;
    bool valid;
};

// ── Block list (max 10 entries) ──────────────────────
#define MAX_BLOCKS 10

struct BlockEntry {
    char type[16];        // "ip", "port", "proto"
    char value[64];       // IP, port, or protocol
    bool active;
    unsigned long created_at;
};

BlockEntry blockList[MAX_BLOCKS];
int blockCount = 0;

// ── Statistics ───────────────────────────────────────
struct BlockStats {
    unsigned long packetsDropped = 0;
    unsigned long blocksApplied = 0;
    unsigned long commandsReceived = 0;
    unsigned long commandsFailed = 0;
};

BlockStats blockStats;

// ─────────────────────────────────────────────────────
// BLOCKING LOGIC
// ─────────────────────────────────────────────────────

bool shouldDropPacket(const uint8_t* ip_src, const uint8_t* ip_dst, 
                      uint16_t port_src, uint16_t port_dst, uint8_t proto) {
    /**
     * Check if packet should be dropped based on block list.
     * For future implementation - currently just returns false.
     */
    
    for (int i = 0; i < blockCount; i++) {
        if (!blockList[i].active) continue;
        
        // Block by source IP
        if (strcmp(blockList[i].type, "ip") == 0) {
            char target_ip[16];
            sprintf(target_ip, "%d.%d.%d.%d", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
            if (strcmp(target_ip, blockList[i].value) == 0) {
                blockStats.packetsDropped++;
                return true;  // DROP THIS PACKET
            }
        }
        
        // Block by protocol
        if (strcmp(blockList[i].type, "proto") == 0) {
            if ((strcmp(blockList[i].value, "ICMP") == 0 && proto == 1) ||
                (strcmp(blockList[i].value, "TCP") == 0 && proto == 6) ||
                (strcmp(blockList[i].value, "UDP") == 0 && proto == 17)) {
                blockStats.packetsDropped++;
                return true;  // DROP THIS PACKET
            }
        }
        
        // Block by port
        if (strcmp(blockList[i].type, "port") == 0) {
            uint16_t target_port = atoi(blockList[i].value);
            if (port_dst == target_port) {
                blockStats.packetsDropped++;
                return true;  // DROP THIS PACKET
            }
        }
    }
    
    return false;  // ALLOW THIS PACKET
}

void addBlockEntry(const char* type, const char* value) {
    /**
     * Add a new entry to the block list.
     * Returns true if successful, false if list is full.
     */
    if (blockCount >= MAX_BLOCKS) {
        Serial.println("[BLOCK] List full - cannot add more blocks");
        return;
    }
    
    strncpy(blockList[blockCount].type, type, sizeof(blockList[blockCount].type) - 1);
    strncpy(blockList[blockCount].value, value, sizeof(blockList[blockCount].value) - 1);
    blockList[blockCount].active = true;
    blockList[blockCount].created_at = millis();
    
    blockCount++;
    blockStats.blocksApplied++;
    
    Serial.printf("[BLOCK] ✅ Added block: %s %s (total: %d)\n", type, value, blockCount);
}

void removeBlockEntry(int index) {
    /**
     * Remove a block entry by index.
     */
    if (index < 0 || index >= blockCount) return;
    
    blockList[index].active = false;
    Serial.printf("[BLOCK] Removed block #%d\n", index);
}

void clearAllBlocks() {
    /**
     * Clear all blocks.
     */
    blockCount = 0;
    for (int i = 0; i < MAX_BLOCKS; i++) {
        blockList[i].active = false;
    }
    Serial.println("[BLOCK] All blocks cleared");
}

void printBlockList() {
    /**
     * Print current block list for debugging.
     */
    Serial.println("\n[BLOCK] Current Block List:");
    if (blockCount == 0) {
        Serial.println("  (empty)");
        return;
    }
    
    for (int i = 0; i < blockCount; i++) {
        if (blockList[i].active) {
            Serial.printf("  #%d | %s : %s | created %lu ms ago\n",
                i, blockList[i].type, blockList[i].value,
                millis() - blockList[i].created_at);
        }
    }
    Serial.printf("\n  Total: %d | Packets dropped: %lu\n", blockCount, blockStats.packetsDropped);
}

void executeBlockCommand(const BlockCommand& cmd) {
    /**
     * Execute a blocking command from backend.
     * 
     * Examples:
     *   action="block_ip", target="192.168.1.100"
     *   action="block_proto", target="ICMP"
     *   action="block_port", target="443"
     */
    
    blockStats.commandsReceived++;
    
    Serial.printf("[BLOCK:CMD] Received: %s %s (%s)\n", 
        cmd.action, cmd.target, cmd.reason);
    
    if (strcmp(cmd.action, "block_ip") == 0) {
        addBlockEntry("ip", cmd.target);
    }
    else if (strcmp(cmd.action, "block_proto") == 0) {
        addBlockEntry("proto", cmd.target);
    }
    else if (strcmp(cmd.action, "block_port") == 0) {
        addBlockEntry("port", cmd.target);
    }
    else if (strcmp(cmd.action, "drop_traffic") == 0) {
        // Generic drop - typically handled differentally
        Serial.printf("[BLOCK:CMD] Drop traffic: %s\n", cmd.reason);
        // Could add a wildcard block here
    }
    else if (strcmp(cmd.action, "clear_blocks") == 0) {
        clearAllBlocks();
    }
    else {
        blockStats.commandsFailed++;
        Serial.printf("[BLOCK:CMD] Unknown action: %s\n", cmd.action);
    }
}

bool parseBlockCommand(const char* json_str, BlockCommand& cmd) {
    /**
     * Parse blocking command from JSON.
     * 
     * Expected format:
     * {
     *   "cmd_id": "cmd_abc123",
     *   "action": "block_ip",
     *   "target": "192.168.1.100",
     *   "reason": "DDoS Attack"
     * }
     */
    
    StaticJsonDocument<256> doc;
    
    if (deserializeJson(doc, json_str) != DeserializationError::Ok) {
        Serial.println("[BLOCK:JSON] Parse error");
        return false;
    }
    
    strncpy(cmd.cmd_id, doc["cmd_id"] | "", sizeof(cmd.cmd_id) - 1);
    strncpy(cmd.action, doc["action"] | "", sizeof(cmd.action) - 1);
    strncpy(cmd.target, doc["target"] | "", sizeof(cmd.target) - 1);
    strncpy(cmd.reason, doc["reason"] | "", sizeof(cmd.reason) - 1);
    cmd.created_at = millis();
    cmd.valid = true;
    
    return true;
}

#endif // BLOCK_COMMAND_H
