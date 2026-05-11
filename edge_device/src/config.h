#ifndef CONFIG_H
#define CONFIG_H

#define WIFI_SSID        "ASWIN-NEO-666 5876"
#define WIFI_PASSWORD    "8c[26K54"

#define BACKEND_HOST     "192.168.137.1"
#define BACKEND_PORT     5001
#define PREDICT_PATH     "/api/realtime"

#define MQTT_BROKER_HOST "192.168.137.1"
#define MQTT_BROKER_PORT 1883
#define MQTT_USERNAME    ""
#define MQTT_PASSWORD    ""

#define DEVICE_ID        "ESP32E-01"

#define LED_STATUS       2
#define LED_ALERT        4
#define BTN_TEST         0
#define BTN_CLEAR_CACHE  35
#define DHT_PIN          15
#define DHT_TYPE         DHT22

#define SAMPLE_MS            500UL
#define FLOW_RESET_MS        5000UL
#define HEARTBEAT_MS         30000UL
#define SENSOR_INTERVAL_MS   30000UL

#define Z_THRESHOLD      2.0f
#define WINDOW_SIZE      30

#define CACHE_MAX_SIZE   50
#define CACHE_SIM_THRESH 0.95f

#define USE_MQTT         true
#define USE_HTTP_FB      true

#endif
