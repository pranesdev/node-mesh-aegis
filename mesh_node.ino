// =============================================================================
//  mesh_node.ino  —  Predictive Self-Healing Maritime Mesh  (single-file)
//
//  One file, one upload. All tunables, packet struct, PMA* routing,
//  scheduler, anomaly, buffer, telemetry, WiFi uplink — everything
//  baked in. Compiles in Arduino IDE with the ESP32 board package.
//
//  AUTO-ROLE FROM MAC (no #define per board):
//    - The board whose MAC last byte == GATEWAY_MAC_BYTE becomes the gateway.
//      It connects to WiFi and POSTs aggregated telemetry to the backend.
//    - All other boards are mesh sensors/relays (ESP-NOW only, no WiFi).
//    - Mesh nodes auto-assign their node ID = MAC last byte (1..254).
//
//  FLASH THE SAME .ino TO ALL BOARDS. Pick one board to be the gateway by
//  setting GATEWAY_MAC_BYTE below to its MAC's last byte (read from Serial
//  Monitor at first boot).
// =============================================================================

#include <Arduino.h>
#include <WiFi.h>
#include <esp_now.h>
#include <LittleFS.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// =============================================================================
//  0. COMPILE-TIME CONFIG — edit before flashing
// =============================================================================

// ---- WiFi (gateway only) ---------------------------------------------------
// Hard-coded for the Galaxy A16 5G phone hotspot.
#define WIFI_SSID       "Galaxy A16 5G 8337"
#define WIFI_PASS       "2008sj2114"

// ---- Backend (gateway only) ------------------------------------------------
// Render URL. The gateway POSTs NDJSON to {BASE}/ingest every 1 s.
#define BACKEND_BASE    "https://node-mesh-aegis-2.onrender.com"
#define BACKEND_INGEST  BACKEND_BASE "/ingest"

// ---- Gateway identity ------------------------------------------------------
// Set this to the LAST BYTE of the MAC of the board you want to act as gateway.
// To find it: flash once with the Serial line that prints "mac=...", then
// re-flash with the matching byte below.
// Current gateway board: MAC last byte 0x3F (= id 63).
#define GATEWAY_MAC_BYTE  0x3F

// =============================================================================
//  1. BOARD PINS  (ESP32-WROOM-32 DevKit v1)
// =============================================================================
#define PIN_SENSOR_0          32
#define PIN_SENSOR_1          33
#define PIN_BATTERY_ADC       34
#define PIN_LED_OK            25
#define PIN_LED_ALERT         26
#define PIN_BTN_BOOT           0

// =============================================================================
//  2. TUNABLES
// =============================================================================
#define MAX_NEIGHBORS             8
#define DEDUP_CACHE_SIZE         64

#define HELLO_INTERVAL_MS      1000
#define HELLO_STALE_MS         3000
#define HELLO_DEAD_MS          6000

#define ALPHA_EWMA            0.2f
#define PRED_SLOPE_THRESH    -0.03f
#define PRED_TREND_COUNT        3
#define PRED_WINDOW_MS       5000
#define THRESHOLD_HARD         -70

#define ALPHA_ETX             0.2f
#define BATTERY_LOW_THRESH      20

// PMA* edge-cost weights
#define W_RSSI                0.35f
#define W_ETX                 0.30f
#define W_BATTERY             0.15f
#define W_HOPS                0.10f
#define W_RISK                0.10f
#define ROUTE_SWITCH_MARGIN   0.15f
#define PACKET_TTL_MAX          5

// Anomaly detection (Welford)
#define ANOM_WIN              32
#define ANOM_Z_THRESH        4.0f
#define ANOM_JUMP_THRESH     6.0f

// Onboard buffer
#define BUFFER_FILE          "/buf"
#define BUFFER_MAX_ATTEMPTS     6

// Gateway uplink
#define UPLINK_INTERVAL_MS   1000
#define UPLINK_RING_SIZE       20
#define UPLINK_HTTP_TIMEOUT  4000

// =============================================================================
//  3. PROTOCOL
// =============================================================================
enum msg_type : uint8_t {
    HELLO         = 0x01,
    DATA          = 0x02,
    ACK           = 0x03,
    CONTROL       = 0x04,
    OTA           = 0x05,
    ANOM          = 0x06,
    TELEMETRY_AGG = 0x07
};
enum prio : uint8_t { BEST_EFFORT = 0, RELIABLE = 1, CRITICAL = 2 };
enum role_t : uint8_t { ROLE_SENSOR = 0, ROLE_RELAY = 1, ROLE_GW = 2 };

typedef struct __attribute__((packed)) {
    uint8_t  type, ver, prio, qos, src, dst, hop, ttl;
    uint32_t seq;
    int8_t   rssi;
    uint8_t  payload[220];
    uint16_t crc;
} mesh_pkt_t;

typedef struct __attribute__((packed)) {
    uint8_t battery;
    uint8_t role;
    uint8_t etx_est_x10;
    uint8_t reserved[5];
} hello_payload_t;

typedef struct {
    uint8_t  id;
    uint8_t  mac[6];
    int8_t   rssi;
    float    ewma_rssi;
    int8_t   ewma_hist[3];
    uint8_t  hist_idx;
    float    slope_hist[3];
    uint8_t  slope_idx;
    float    pred_rssi;
    uint16_t sent_cnt, ack_cnt;
    float    etx, ewma_etx;
    uint8_t  battery, hop_count, risk;
    uint32_t last_seen_ms;
} neighbor_t;

// =============================================================================
//  4. GLOBAL STATE
// =============================================================================
static const uint8_t BCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

uint8_t        my_id            = 0;       // resolved at boot from MAC
uint8_t        my_role          = ROLE_SENSOR;
bool           is_gateway       = false;   // resolved at boot
uint8_t        my_battery       = 90;
uint8_t        current_next_hop = 0xFF;
uint8_t        route_mode       = 0;       // 0=RSSI, 1=ETX
RTC_DATA_ATTR uint32_t seq_counter = 0;

neighbor_t neighbors[MAX_NEIGHBORS];
uint8_t    n_neighbors = 0;

QueueHandle_t inbox_q;
QueueHandle_t q_crit, q_rel, q_be;

struct dedup_entry { uint32_t key; bool used; };
static dedup_entry dedup[DEDUP_CACHE_SIZE];
static uint8_t     dedup_head = 0;

struct anomaly_state {
    float mean, var;
    int   n, prev;
    bool  bootstrapped;
    uint8_t last_flag;
};
static anomaly_state anomaly_s0, anomaly_s1;

// ---- Gateway uplink ring buffer -------------------------------------------
// Each slot holds one NDJSON payload (one record per known node).
static char uplink_ring[UPLINK_RING_SIZE][768];
static uint8_t uplink_head = 0;    // next slot to write
static uint8_t uplink_count = 0;   // how many slots are populated
static bool   uplink_pending[UPLINK_RING_SIZE] = {false};

// =============================================================================
//  5. HELPERS
// =============================================================================
static inline float clamp01(float v) {
    return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v);
}
static float rssiCost(int8_t r) {
    return clamp01(1.0f - (float)(r + 100) / 70.0f);
}
static float etxCost(float e) {
    if (e < 1) e = 1; if (e > 5) e = 5;
    return clamp01((e - 1) / 4);
}
static float batteryCost(uint8_t b) {
    if (b > 100) b = 100;
    return clamp01(1.0f - (float)b / 100);
}
static float riskCost(uint8_t r) { return r ? 1.0f : 0.0f; }
static float hopCost(uint8_t h)  { return clamp01((float)h / PACKET_TTL_MAX); }

static uint16_t crc16(const uint8_t *d, int n) {
    uint16_t c = 0xFFFF;
    for (int i = 0; i < n; ++i) {
        c ^= d[i] << 8;
        for (int k = 0; k < 8; ++k) c = (c & 0x8000) ? (c << 1) ^ 0x1021 : c << 1;
    }
    return c;
}

static bool dedup_seen(uint32_t key) {
    for (uint8_t i = 0; i < DEDUP_CACHE_SIZE; ++i)
        if (dedup[i].used && dedup[i].key == key) return true;
    dedup[dedup_head] = {key, true};
    dedup_head = (dedup_head + 1) % DEDUP_CACHE_SIZE;
    return false;
}

// =============================================================================
//  6. NEIGHBOUR / PREDICTOR
// =============================================================================
static void add_peer(const uint8_t *mac) {
    esp_now_peer_info_t pi = {};
    memcpy(pi.peer_addr, mac, 6);
    pi.channel = 0; pi.encrypt = false;
    esp_now_add_peer(&pi);
}

static void neighbor_update(const mesh_pkt_t &p, const uint8_t *mac) {
    if (p.type != HELLO) return;
    uint8_t idx = 0xFF;
    for (uint8_t i = 0; i < n_neighbors; ++i)
        if (neighbors[i].id == p.src) { idx = i; break; }
    if (idx == 0xFF) {
        if (n_neighbors >= MAX_NEIGHBORS) return;
        idx = n_neighbors++;
        neighbors[idx].id = p.src;
        memcpy(neighbors[idx].mac, mac, 6);
        add_peer(mac);
        neighbors[idx].ewma_rssi = (float)p.rssi;
        neighbors[idx].ewma_etx  = 1.0f;
        neighbors[idx].hist_idx  = 0;
        neighbors[idx].slope_idx = 0;
        for (uint8_t i = 0; i < 3; ++i) {
            neighbors[idx].ewma_hist[i] = p.rssi;
            neighbors[idx].slope_hist[i] = 0;
        }
    }
    neighbor_t &nb = neighbors[idx];
    nb.rssi = p.rssi;
    nb.last_seen_ms = millis();
    const hello_payload_t *hp = (const hello_payload_t *)p.payload;
    nb.battery = hp->battery;
    if (hp->etx_est_x10 > 0)
        nb.ewma_etx = (float)hp->etx_est_x10 / 10.0f;

    float prev = nb.ewma_rssi;
    float now  = ALPHA_EWMA * (float)nb.rssi + (1 - ALPHA_EWMA) * prev;
    nb.ewma_hist[nb.hist_idx] = (int8_t)prev;
    nb.hist_idx = (nb.hist_idx + 1) % 3;
    nb.ewma_rssi = now;

    float slope = (nb.ewma_rssi - prev) / 1.0f;
    nb.slope_hist[nb.slope_idx] = slope;
    nb.slope_idx = (nb.slope_idx + 1) % 3;

    float avg = 0;
    for (uint8_t i = 0; i < 3; ++i) avg += nb.slope_hist[i];
    avg /= 3.0f;
    nb.pred_rssi = nb.ewma_rssi + avg * (PRED_WINDOW_MS / 1000.0f);
}

static void compute_costs_and_risk() {
    for (uint8_t i = 0; i < n_neighbors; ++i) {
        neighbor_t &nb = neighbors[i];
        if (nb.sent_cnt) {
            float dr = (float)nb.ack_cnt / (float)nb.sent_cnt;
            if (dr < 0.01f) dr = 0.01f;
            float e = 1.0f / dr;
            nb.ewma_etx = ALPHA_ETX * e + (1 - ALPHA_ETX) * nb.ewma_etx;
            nb.etx = e;
        }
        nb.risk = 0;
        if (nb.pred_rssi < THRESHOLD_HARD) nb.risk = 1;
        bool dec = true;
        for (uint8_t s = 0; s < 3; ++s)
            if (nb.slope_hist[s] >= PRED_SLOPE_THRESH) { dec = false; break; }
        if (dec) nb.risk = 1;
        if (nb.ewma_etx > 2.0f) nb.risk = 1;
        if (nb.battery < BATTERY_LOW_THRESH) nb.risk = 1;
    }
    uint32_t now = millis();
    for (int i = (int)n_neighbors - 1; i >= 0; --i) {
        if (now - neighbors[i].last_seen_ms > HELLO_DEAD_MS) {
            for (uint8_t j = i; j + 1 < n_neighbors; ++j) neighbors[j] = neighbors[j+1];
            n_neighbors--;
        }
    }
}

static float edge_cost(const neighbor_t &nb) {
    float rc = rssiCost(nb.rssi);
    float ec = route_mode ? etxCost(nb.ewma_etx) : rssiCost(nb.rssi);
    float bc = batteryCost(nb.battery);
    float hc = hopCost(nb.hop_count);
    float rk = riskCost(nb.risk);
    if (route_mode) return W_RSSI*rc + W_ETX*ec + W_BATTERY*bc + W_HOPS*hc + W_RISK*rk;
    else           return W_RSSI*rc + W_BATTERY*bc + W_HOPS*hc + W_RISK*rk;
}

// =============================================================================
//  7. PMA*  (Predictive Maritime A*)
// =============================================================================
struct a_node { uint8_t id; float g, f; uint8_t parent; bool opened, closed; };

static uint8_t pma_next_hop(uint8_t src) {
    const uint8_t MAX_N = MAX_NEIGHBORS + 1;
    a_node nodes[MAX_N];
    uint8_t nc = 0;
    nodes[nc++] = {src, 0, 0, 0xFF, false, false};
    for (uint8_t i = 0; i < n_neighbors; ++i)
        nodes[nc++] = {neighbors[i].id, 1e9f, 1e9f, 0xFF, false, false};

    auto idx_of = [&](uint8_t id) -> int8_t {
        for (uint8_t i = 0; i < nc; ++i) if (nodes[i].id == id) return i;
        return -1;
    };

    uint8_t open[MAX_N]; uint8_t olen = 0;
    auto push = [&](uint8_t i) {
        open[olen++] = i;
        for (int x = (int)olen-1; x > 0;) {
            int p = (x-1)/2;
            if (nodes[open[x]].f < nodes[open[p]].f) {
                uint8_t t = open[x]; open[x] = open[p]; open[p] = t;
                x = p;
            } else break;
        }
    };
    auto pop = [&]() -> uint8_t {
        uint8_t top = open[0];
        open[0] = open[--olen];
        for (uint8_t x = 0;;) {
            uint8_t l = x*2+1, r = l+1, m = x;
            if (l < olen && nodes[open[l]].f < nodes[open[m]].f) m = l;
            if (r < olen && nodes[open[r]].f < nodes[open[m]].f) m = r;
            if (m == x) break;
            uint8_t t = open[x]; open[x] = open[m]; open[m] = t;
            x = m;
        }
        return top;
    };

    nodes[0].f = 0;
    push(0);

    while (olen) {
        uint8_t ci = pop();
        a_node &c = nodes[ci];
        if (c.id == my_id && is_gateway) {
            // gateway reached itself; the gateway is the destination
            return 0xFF;
        }
        if (is_gateway && c.id == my_id) return 0xFF;
        if (!is_gateway && c.id == 0xFF) {
            // unreachable; this branch won't trigger in practice — we route to gateway by MAC
        }
        if (c.closed) continue;
        c.closed = true;
        for (uint8_t n = 0; n < n_neighbors; ++n) {
            neighbor_t &nbr = neighbors[n];
            if (nbr.id == c.id) continue;
            int8_t ni = idx_of(nbr.id);
            if (ni < 0) continue;
            a_node &s = nodes[ni];
            if (s.closed) continue;
            float tg = c.g + edge_cost(nbr);
            if (!s.opened || tg < s.g) {
                s.g = tg; s.f = tg; s.parent = c.id;
                if (!s.opened) { s.opened = true; push(ni); }
            }
        }
    }
    return 0xFF;
}

// Gateway is the destination for mesh nodes; pick the first neighbor that
// matches a known gateway by id (set below) or — simpler — flood upward.
// We treat the gateway as "any neighbor with role == ROLE_GW" or with the
// preconfigured gateway id broadcast via HELLO.role.
static uint8_t gateway_id_cache = 0xFF;

// =============================================================================
//  8. ANOMALY  (Welford online)
// =============================================================================
static uint8_t anomaly_push(anomaly_state &s, int x) {
    s.n++;
    float d = x - s.mean;
    s.mean += d / s.n;
    s.var += d * (x - s.mean);
    if (s.n < ANOM_WIN) { s.prev = x; return 0; }
    if (!s.bootstrapped) { s.bootstrapped = true; s.prev = x; return 0; }
    float sd = sqrtf(s.var / s.n);
    if (sd < 0.001f) sd = 0.001f;
    uint8_t flag = 0;
    if (fabsf(x - s.mean) > ANOM_Z_THRESH * sd) flag = 1;
    else if (fabsf(x - s.prev) > ANOM_JUMP_THRESH * sd) flag = 2;
    s.prev = x;
    s.last_flag = flag;
    return flag;
}

// =============================================================================
//  9. RADIO
// =============================================================================
// ESP32 3.x ESP-NOW API: callbacks receive info structs, not raw MAC pointers.
static void onDataSent(const wifi_tx_info_t *, esp_now_send_status_t) {}
static void onDataRecv(const esp_now_recv_info *recv_info, const uint8_t *data, int len) {
    const uint8_t *mac = recv_info ? recv_info->src_addr : nullptr;
    if (!mac) return;
    if (len < (int)sizeof(mesh_pkt_t)) return;
    mesh_pkt_t p; memcpy(&p, data, sizeof(p));
    if (p.crc != crc16(data, sizeof(p) - 2)) return;
    if (p.type == HELLO) {
        const hello_payload_t *hp = (const hello_payload_t *)p.payload;
        if (hp->role == ROLE_GW) gateway_id_cache = p.src;
        neighbor_update(p, mac);
        return;
    }
    QueueHandle_t q;
    if (p.prio == CRITICAL)      q = q_crit;
    else if (p.prio == RELIABLE) q = q_rel;
    else                         q = q_be;
    BaseType_t hp2 = pdFALSE;
    xQueueSendFromISR(q, &p, &hp2);
}

static void radio_init() {
    WiFi.mode(WIFI_STA);
    if (esp_now_init() != ESP_OK) { Serial.println(F("esp_now fail")); return; }
    esp_now_register_send_cb(onDataSent);
    esp_now_register_recv_cb(onDataRecv);
    esp_now_peer_info_t bc = {};
    memcpy(bc.peer_addr, BCAST, 6);
    bc.channel = 0; bc.encrypt = false;
    esp_now_add_peer(&bc);
}

// =============================================================================
//  10. FORWARDING + BUFFER + ACK
// =============================================================================
static void send_unicast(uint8_t next_id, const mesh_pkt_t &p) {
    for (uint8_t i = 0; i < n_neighbors; ++i)
        if (neighbors[i].id == next_id) {
            mesh_pkt_t q = p;
            q.crc = crc16((uint8_t*)&q, sizeof(q) - 2);
            esp_now_send(neighbors[i].mac, (uint8_t*)&q, sizeof(q));
            neighbors[i].sent_cnt++;
            return;
        }
}

static void process_queue(QueueHandle_t q, prio /*p*/) {
    mesh_pkt_t p;
    while (xQueueReceive(q, &p, 0) == pdTRUE) {
        uint32_t key = ((uint32_t)p.src << 16) | (p.seq & 0xFFFF);
        if (dedup_seen(key)) continue;
        if (p.ttl == 0) continue;
        p.ttl--;

        if (p.dst == my_id) {
            if (p.qos > 0) {
                mesh_pkt_t ack = {};
                ack.type = ACK; ack.ver = 1;
                ack.src = my_id; ack.dst = p.src;
                ack.seq = p.seq;
                ack.crc = crc16((uint8_t*)&ack, sizeof(ack) - 2);
                send_unicast(p.src, ack);
            }
            continue;
        }
        // Pick next hop: gateway routes nowhere; sensor/relay picks toward gateway.
        uint8_t nh;
        if (is_gateway) {
            nh = 0xFF;
        } else if (gateway_id_cache != 0xFF) {
            // direct A* with gateway as destination (cheap shortcut: nearest neighbor to gateway)
            // For simplicity, if any neighbor is the gateway, pick that one.
            for (uint8_t i = 0; i < n_neighbors; ++i)
                if (neighbors[i].id == gateway_id_cache) { nh = neighbors[i].id; break; }
            if (nh == 0xFF) nh = pma_next_hop(my_id);
        } else {
            nh = pma_next_hop(my_id);
        }

        if (nh == 0xFF) {
            File f = LittleFS.open(BUFFER_FILE, "a");
            if (f) { f.write((uint8_t*)&p, sizeof(p)); f.close(); }
            continue;
        }
        send_unicast(nh, p);
    }
}

static void drain_buffer() {
    if (!LittleFS.exists(BUFFER_FILE)) return;
    File f = LittleFS.open(BUFFER_FILE, "r");
    if (!f) return;
    mesh_pkt_t p;
    bool any = false;
    while ((int)f.available() >= (int)sizeof(p)) {
        f.readBytes((char*)&p, sizeof(p));
        uint8_t nh;
        if (is_gateway) nh = 0xFF;
        else if (gateway_id_cache != 0xFF) {
            nh = 0xFF;
            for (uint8_t i = 0; i < n_neighbors; ++i)
                if (neighbors[i].id == gateway_id_cache) { nh = neighbors[i].id; break; }
            if (nh == 0xFF) nh = pma_next_hop(my_id);
        } else {
            nh = pma_next_hop(my_id);
        }
        if (nh == 0xFF) { any = true; break; }
        send_unicast(nh, p);
        any = true;
    }
    f.close();
    if (any) LittleFS.remove(BUFFER_FILE);
}

// =============================================================================
//  11. SCHEDULER TICKS
// =============================================================================
static void tick_heartbeat() {
    mesh_pkt_t p = {};
    p.type = HELLO; p.ver = 1;
    p.src = my_id; p.dst = 0xFF;
    p.prio = BEST_EFFORT; p.qos = 0;
    p.seq = ++seq_counter;
    p.rssi = (int8_t)WiFi.RSSI();
    hello_payload_t hp = {};
    hp.battery = my_battery;
    hp.role = my_role;
    hp.etx_est_x10 = (uint8_t)(1 * 10);
    memcpy(p.payload, &hp, sizeof(hp));
    p.crc = crc16((uint8_t*)&p, sizeof(p) - 2);
    esp_now_send(BCAST, (uint8_t*)&p, sizeof(p));
}

static void tick_anomaly() {
    int a0 = analogRead(PIN_SENSOR_0);
    int a1 = analogRead(PIN_SENSOR_1);
    uint8_t f0 = anomaly_push(anomaly_s0, a0);
    uint8_t f1 = anomaly_push(anomaly_s1, a1);

    static uint32_t last_led = 0;
    if (f0 || f1) {
        if (millis() - last_led > 120) {
            digitalWrite(PIN_LED_ALERT, !digitalRead(PIN_LED_ALERT));
            last_led = millis();
        }
        digitalWrite(PIN_LED_OK, LOW);
    } else {
        digitalWrite(PIN_LED_ALERT, LOW);
        digitalWrite(PIN_LED_OK, HIGH);
    }

    if (f0 || f1) {
        mesh_pkt_t p = {};
        p.type = ANOM; p.ver = 1; p.prio = RELIABLE;
        p.src = my_id; p.dst = 0xFF;     // broadcast to gateway via neighbors
        p.seq = ++seq_counter;
        p.payload[0] = my_id;
        p.payload[1] = f0;
        p.payload[2] = f1;
        p.crc = crc16((uint8_t*)&p, sizeof(p) - 2);
        uint8_t nh = 0xFF;
        if (gateway_id_cache != 0xFF) {
            for (uint8_t i = 0; i < n_neighbors; ++i)
                if (neighbors[i].id == gateway_id_cache) { nh = neighbors[i].id; break; }
        }
        if (nh == 0xFF) nh = pma_next_hop(my_id);
        if (nh != 0xFF) send_unicast(nh, p);
    }
}

// Build a JSON record for one node (gateway uses this for uplink).
static void node_json(uint8_t id, uint8_t role, uint8_t bat, int8_t rssi_self, char *out, size_t outlen) {
    StaticJsonDocument<512> doc;
    doc["node"]   = id;
    doc["role"]   = role;
    doc["rssi"]   = rssi_self;
    doc["bat"]    = bat;
    JsonArray nbrs = doc.createNestedArray("nbrs");
    for (uint8_t i = 0; i < n_neighbors; ++i) {
        JsonObject o = nbrs.createNestedObject();
        o["id"]   = neighbors[i].id;
        o["rssi"] = neighbors[i].rssi;
        o["etx"]  = (uint8_t)(neighbors[i].ewma_etx * 10);
        o["bat"]  = neighbors[i].battery;
        o["risk"] = neighbors[i].risk;
        o["hop"]  = neighbors[i].hop_count;
    }
    serializeJson(doc, out, outlen);
}

static void tick_telemetry() {
    // Local Serial dump (unchanged behavior).
    Serial.print(F("{\"id\":")); Serial.print(my_id);
    Serial.print(F(",\"role\":")); Serial.print(my_role);
    Serial.print(F(",\"bat\":")); Serial.print(my_battery);
    Serial.print(F(",\"mode\":")); Serial.print(route_mode);
    Serial.print(F(",\"nb\":")); Serial.print(n_neighbors);
    Serial.print(F(",\"route\":")); Serial.print(current_next_hop);
    Serial.print(F(",\"nbrs\":["));
    for (uint8_t i = 0; i < n_neighbors; ++i) {
        if (i) Serial.print(F(","));
        Serial.printf("{\"id\":%u,\"rssi\":%d,\"etx\":%u,\"bat\":%u,\"risk\":%u,\"hop\":%u}",
            neighbors[i].id, neighbors[i].rssi,
            (uint8_t)(neighbors[i].ewma_etx * 10),
            neighbors[i].battery, neighbors[i].risk,
            neighbors[i].hop_count);
    }
    Serial.print(F("]}\n"));

    // Gateway: build NDJSON uplink payload (one record per known mesh node).
    if (is_gateway) {
        StaticJsonDocument<1024> doc;
        JsonArray arr = doc.to<JsonArray>();
        // First record: the gateway itself.
        {
            JsonObject o = arr.createNestedObject();
            o["node"] = my_id;
            o["role"] = my_role;
            o["rssi"] = (int8_t)WiFi.RSSI();
            o["bat"]  = my_battery;
            JsonArray nb = o.createNestedArray("nbrs");
            for (uint8_t i = 0; i < n_neighbors; ++i) {
                JsonObject x = nb.createNestedObject();
                x["id"]   = neighbors[i].id;
                x["rssi"] = neighbors[i].rssi;
                x["etx"]  = (uint8_t)(neighbors[i].ewma_etx * 10);
                x["bat"]  = neighbors[i].battery;
                x["risk"] = neighbors[i].risk;
                x["hop"]  = neighbors[i].hop_count;
            }
        }
        // Then one record per neighbor that has battery info (mesh nodes).
        for (uint8_t i = 0; i < n_neighbors; ++i) {
            JsonObject o = arr.createNestedObject();
            o["node"] = neighbors[i].id;
            o["role"] = (neighbors[i].risk ? ROLE_SENSOR : ROLE_RELAY);
            o["rssi"] = neighbors[i].rssi;
            o["bat"]  = neighbors[i].battery;
            JsonArray nb = o.createNestedArray("nbrs");
            // (Mesh nodes don't share their full neighbor table over the air,
            //  so we report what the gateway knows about them.)
        }
        // Serialize NDJSON.
        char buf[1024];
        size_t off = 0;
        for (JsonObject o : arr) {
            size_t n = serializeJson(o, buf + off, sizeof(buf) - off - 2);
            buf[off + n] = '\n';
            off += n + 1;
        }
        buf[off] = '\0';
        // Stage into ring buffer.
        strncpy(uplink_ring[uplink_head], buf, sizeof(uplink_ring[0]) - 1);
        uplink_ring[uplink_head][sizeof(uplink_ring[0]) - 1] = '\0';
        uplink_pending[uplink_head] = true;
        uplink_head = (uplink_head + 1) % UPLINK_RING_SIZE;
        if (uplink_count < UPLINK_RING_SIZE) uplink_count++;
    }
}

static void tick_role() {
    if (is_gateway) { my_role = ROLE_GW; return; }
    my_role = (n_neighbors >= 3) ? ROLE_RELAY : ROLE_SENSOR;
}

// =============================================================================
//  12. GATEWAY UPLINK (WiFi + HTTP POST)
// =============================================================================
// Guard against re-entrant WiFi.begin() calls. The driver errors out if
// WiFi.mode()/WiFi.begin() is invoked while a connection attempt is in
// flight, so we only start a connection once and let the driver retry.
static bool wifi_connect_started = false;
static uint32_t wifi_connect_started_ms = 0;
static bool wifi_was_connected = false;

static void wifi_connect() {
    if (!is_gateway) return;
    if (WiFi.status() == WL_CONNECTED) return;
    if (wifi_connect_started) {
        // Give the driver ~15 s before giving up and re-trying fresh.
        if (millis() - wifi_connect_started_ms < 15000) return;
        Serial.println(F("[wifi] giving up, restarting connection"));
        WiFi.disconnect();
        wifi_connect_started = false;
    }
    Serial.printf("[wifi] connecting to %s ...\n", WIFI_SSID);
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    wifi_connect_started = true;
    wifi_connect_started_ms = millis();
}

static void tick_uplink() {
    if (!is_gateway) return;

    bool connected = (WiFi.status() == WL_CONNECTED);
    if (connected && !wifi_was_connected) {
        Serial.printf("[wifi] connected, IP %s\n",
                      WiFi.localIP().toString().c_str());
        wifi_was_connected = true;
    } else if (!connected) {
        wifi_was_connected = false;
        wifi_connect();
        return;
    }

    if (uplink_count == 0) return;

    // Find oldest pending slot.
    uint8_t slot = (uplink_head + UPLINK_RING_SIZE - uplink_count) % UPLINK_RING_SIZE;
    if (!uplink_pending[slot]) {
        // nothing pending in head window; advance
        uplink_count--;
        return;
    }

    HTTPClient http;
    http.begin(BACKEND_INGEST);
    http.setTimeout(UPLINK_HTTP_TIMEOUT);
    http.addHeader("Content-Type", "application/x-ndjson");
    int code = http.POST((uint8_t*)uplink_ring[slot], strlen(uplink_ring[slot]));
    if (code > 0) {
        Serial.printf("[uplink] %s -> %d\n", BACKEND_INGEST, code);
        uplink_pending[slot] = false;
        uplink_count--;
    } else {
        Serial.printf("[uplink] POST failed: %s (will retry)\n",
                      HTTPClient::errorToString(code).c_str());
    }
    http.end();
}

// =============================================================================
//  13. SETUP / LOOP
// =============================================================================
void setup() {
    Serial.begin(115200);
    delay(200);
    Serial.println(F("mesh_node booting..."));

    // ---- GPIO --------------------------------------------------------------
    pinMode(PIN_LED_OK,    OUTPUT);
    pinMode(PIN_LED_ALERT, OUTPUT);
    pinMode(PIN_BTN_BOOT,  INPUT_PULLUP);
    analogReadResolution(12);
    digitalWrite(PIN_LED_OK, HIGH);

    // ---- Resolve identity from MAC -----------------------------------------
    uint8_t mac[6];
    WiFi.macAddress(mac);   // works even before WiFi.begin()
    uint8_t last_byte = mac[5];
    is_gateway = (last_byte == GATEWAY_MAC_BYTE);
    my_id = last_byte;
    my_role = is_gateway ? ROLE_GW : ROLE_SENSOR;
    Serial.printf("{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\",\"id\":%u,\"role\":\"%s\"}\n",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                  my_id, is_gateway ? "GATEWAY" : "NODE");

    // ---- Battery read (averaged, 1/2 divider assumed) -----------------------
    uint32_t sum = 0;
    for (int i = 0; i < 16; ++i) sum += analogRead(PIN_BATTERY_ADC);
    float v = (float)(sum / 16) / 4095.0f * 3.3f * 2.0f;
    int pct = (int)((v - 3.0f) / 1.2f * 100.0f);
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    my_battery = (uint8_t)pct;

    // ---- Boot button held at reset -> force this node to be the gateway ----
    if (digitalRead(PIN_BTN_BOOT) == LOW) {
        is_gateway = true;
        my_role = ROLE_GW;
        Serial.println(F("boot button held -> forcing gateway role"));
    }

    // ---- FS, queues, radio -------------------------------------------------
    if (!LittleFS.begin()) Serial.println(F("FS fail"));
    q_crit = xQueueCreate(16, sizeof(mesh_pkt_t));
    q_rel  = xQueueCreate(32, sizeof(mesh_pkt_t));
    q_be   = xQueueCreate(32, sizeof(mesh_pkt_t));
    radio_init();

    // Gateway: bring up WiFi asynchronously; loop() retries.
    if (is_gateway) wifi_connect();

    Serial.printf("{\"boot\":{\"id\":%u,\"role\":%u,\"bat\":%u,\"is_gw\":%s}}\n",
                  my_id, my_role, my_battery, is_gateway ? "true" : "false");
}

uint32_t last_hb = 0, last_cost = 0, last_telem = 0,
         last_anom = 0, last_role = 0, last_drain = 0,
         last_uplink = 0;

void loop() {
    uint32_t now = millis();

    process_queue(q_crit, CRITICAL);
    process_queue(q_rel,  RELIABLE);
    process_queue(q_be,   BEST_EFFORT);

    if (now - last_hb    >= HELLO_INTERVAL_MS) { tick_heartbeat(); last_hb    = now; }
    if (now - last_cost  >= 1000)              {
        compute_costs_and_risk();
        uint8_t new_nh = pma_next_hop(my_id);
        if (new_nh != 0xFF && new_nh != current_next_hop) current_next_hop = new_nh;
        last_cost = now;
    }
    if (now - last_anom  >= 100)               { tick_anomaly();   last_anom  = now; }
    if (now - last_drain >= 1000)              { drain_buffer();   last_drain = now; }
    if (now - last_role  >= 30000)             { tick_role();      last_role  = now; }
    if (now - last_telem >= 1000)              { tick_telemetry(); last_telem = now; }
    if (now - last_uplink >= UPLINK_INTERVAL_MS && is_gateway) {
        tick_uplink(); last_uplink = now;
    }

    if (Serial.available()) {
        String s = Serial.readStringUntil('\n');
        s.trim();
        if (s == "MODE:ETX")       route_mode = 1;
        else if (s == "MODE:RSSI") route_mode = 0;
    }
}
