#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <stdint.h>

#define BEACON_INTERVAL 0x0064 // 100 TU
#define CAPABILITY_INFO 0x0401 // ESS + Short Preamble

// Radiotap Header (16 bytes)
struct radiotap_header {
    uint8_t  version;
    uint8_t  pad;
    uint16_t len;
    uint32_t present_flags;
    uint8_t  rate;
    uint16_t channel_freq;
    uint16_t channel_flags;
    uint8_t  antenna_signal;
    uint8_t  antenna;
};

// 802.11 Beacon Frame Header (24 bytes)
struct ieee80211_beacon_frame {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  dest_addr[6];
    uint8_t  src_addr[6];
    uint8_t  bssid[6];
    uint16_t seq_ctrl;
};

// Fixed Parameters (12 bytes)
struct fixed_parameters {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capability_info;
};

// SSID Tagged Parameter
struct ssid_tagged_parameter {
    uint8_t tag_number;
    uint8_t tag_length;
    char    ssid[];
};

// 전체 패킷 생성 함수
int create_beacon_frame(uint8_t *packet, const char *ssid, const uint8_t *src_mac);

#endif
