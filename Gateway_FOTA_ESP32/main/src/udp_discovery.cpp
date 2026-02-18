#include "fota/udp_discovery.hpp"

#include <cstring>

#include "esp_log.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

namespace fota
{
static const char* const TAG = "FOTA_UDP";

static bool parse_beacon(const char* msg, DiscoveryResult* out)
{
    if (msg == nullptr || out == nullptr)
    {
        return false;
    }

    // Expected: FOTA_BEACON|<IP>|<PORT>
    static const char kPrefix[] = "FOTA_BEACON|";
    const size_t prefix_len = sizeof(kPrefix) - 1;
    if (strncmp(msg, kPrefix, prefix_len) != 0)
    {
        return false;
    }

    const char* p = msg + prefix_len;
    const char* sep = strchr(p, '|');
    if (sep == nullptr)
    {
        return false;
    }

    std::string ip(p, (size_t)(sep - p));
    const char* port_str = sep + 1;
    if (*port_str == '\0')
    {
        return false;
    }

    char* endp = nullptr;
    long port_l = strtol(port_str, &endp, 10);
    if (endp == port_str || port_l <= 0 || port_l > 65535)
    {
        return false;
    }

    in_addr addr = {};
    if (inet_aton(ip.c_str(), &addr) == 0)
    {
        return false;
    }

    out->server_ip = ip;
    out->server_port = static_cast<uint16_t>(port_l);
    return true;
}

bool udp_wait_for_beacon(uint16_t listen_port, uint32_t timeout_ms, DiscoveryResult* out)
{
    if (out == nullptr)
    {
        return false;
    }

    const int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "socket() failed");
        return false;
    }

    int reuse = 1;
    (void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) != 0)
    {
        ESP_LOGE(TAG, "bind() failed on port %u", (unsigned)listen_port);
        close(sock);
        return false;
    }

    timeval tv = {};
    tv.tv_sec = (time_t)(timeout_ms / 1000U);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000U) * 1000U);
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char rx[256];
    for (;;)
    {
        memset(rx, 0, sizeof(rx));
        sockaddr_in from = {};
        socklen_t fromlen = sizeof(from);

        const int n = recvfrom(sock, rx, (int)sizeof(rx) - 1, 0, (sockaddr*)&from, &fromlen);
        if (n < 0)
        {
            ESP_LOGW(TAG, "recvfrom timeout/fail");
            close(sock);
            return false;
        }

        rx[n] = '\0';
        ESP_LOGI(TAG, "UDP RX: %s", rx);

        DiscoveryResult tmp;
        if (parse_beacon(rx, &tmp))
        {
            *out = tmp;
            ESP_LOGI(TAG, "Beacon OK: server_ip=%s port=%u", out->server_ip.c_str(), (unsigned)out->server_port);
            close(sock);
            return true;
        }

        ESP_LOGW(TAG, "Beacon format invalid");
    }
}
} // namespace fota
