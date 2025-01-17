#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "config.h"
#include "https.c"

void make_https_request(const char *hostname, const char *url)
{
    HTTPS_STATE_T *state = https_init_state(hostname, url);

    u64_t req_start_time = time_us_64();
    err_t err = https_make_request_sync(state);

    if (err != 0)
    {
        printf("Request to https://%s%s FAILED in %.2f ms with error number: %d\n", hostname, url, (float)(time_us_64() - req_start_time) / 1000, err);
        https_free_state(state);
        return;
    }

    printf("Request to https://%s%s SUCCEEDED in %.2f ms\n", hostname, url, (float)(time_us_64() - req_start_time) / 1000);
    https_free_state(state);
    return;
}

int main()
{
    stdio_init_all();

    uint64_t start_time = time_us_64();

    // Initialise the Wi-Fi chip
    if (cyw43_arch_init())
    {
        printf("Wi-Fi init failed\n");
        return -1;
    }

    // Enable wifi station
    cyw43_arch_enable_sta_mode();

    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000))
    {
        printf("failed to connect.\n");
        return 1;
    }

    printf("Connected in %.2f ms\n", (float)(time_us_64() - start_time) / 1000);

    make_https_request("www.google.com", "/");
    make_https_request("www.youtube.com", "/");
    make_https_request("www.facebook.com", "/");
    make_https_request("www.wikipedia.org", "/");
    make_https_request("catfact.ninja", "/fact");

    while (true)
    {
        sleep_ms(1000);
    }
}
