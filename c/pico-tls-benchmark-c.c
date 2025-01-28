#include <stdio.h>

#include "http.c"
#include "https.c"
#include "mbedtls/debug.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#if !defined(WIFI_SSID) || !defined(WIFI_PASSWORD)
#include "config.h"
#endif

void make_https_request_test(const char *hostname, const char *url,
                             const char *cert_type) {
    HTTPS_STATE_T *state = https_init_state(hostname, url);

    u64_t req_start_time = time_us_64();
    int err = https_make_request_sync(state);

    if (err != 0) {
        printf(
            "Request to https://%s%s FAILED in %.2fms with error number: %d\n",
            hostname, url, (float)(time_us_64() - req_start_time) / 1000, err);
        https_free_state(state);
        return;
    }

    printf(
        "Request to https://%s%s SUCCEEDED in %.2fms | tcp_connect time: "
        "%.2fms | tls_open_connection time: %.2fms | cert: %s\n",
        hostname, url, (float)(time_us_64() - req_start_time) / 1000,
        (float)(state->tls_state->tcp_state->tcp_connect_end_time -
                state->tls_state->tcp_state->tcp_connect_start_time) /
            1000,
        (float)(state->tls_state->handshake_end_time -
                state->tls_state->handshake_start_time) /
            1000,
        cert_type);
    https_free_state(state);
    return;
}

void make_http_request_test(const char *hostname, const char *url) {
    HTTP_STATE_T *state = http_init_state(hostname, url);

    u64_t req_start_time = time_us_64();
    err_t err = http_make_request_sync(state);

    if (err != 0) {
        printf(
            "Request to http://%s%s FAILED in %.2fms with error number: %d\n",
            hostname, url, (float)(time_us_64() - req_start_time) / 1000, err);
        http_free_state(state);
        return;
    }

    printf(
        "Request to http://%s%s SUCCEEDED in %.2fms| tcp_connect time: "
        "%.2fms\n",
        hostname, url, (float)(time_us_64() - req_start_time) / 1000,
        (float)(state->tcp_state->tcp_connect_end_time -
                state->tcp_state->tcp_connect_start_time) /
            1000);
    http_free_state(state);
    return;
}

int main() {
    stdio_init_all();

    uint64_t start_time = time_us_64();

    // Initialise the Wi-Fi chip
    if (cyw43_arch_init()) {
        printf("Wi-Fi init failed\n");
        return -1;
    }

    // Enable wifi station
    cyw43_arch_enable_sta_mode();

#ifndef NDEBUG
    // build for debug (slows down TLS handshakes)
    // Make sure LWIP_DEBUG is 1 (remove #undef LWIP_DEBUG)
    // Turn ON ALTCP_MBEDTLS_DEBUG and ALTCP_MBEDTLS_LIB_DEBUG?
    // enable mbedtls debug below, set to 3 to get details
    // Make sure MBEDTLS_DEBUG_C is defined
    mbedtls_debug_set_threshold(3);
#endif

    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD,
                                           CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("failed to connect.\n");
        return 1;
    }

    printf("Connected in %.2f ms\n", (float)(time_us_64() - start_time) / 1000);

    // make_http_request_test(
    //     "www.google.com",
    //     "/");  // http variant just for good measure, it's the only site that
    //            // allows http from urls used here.
    make_https_request_test("www.google.com", "/", "RSA SHA-256");

    // make_https_request_test("www.youtube.com", "/", "RSA SHA-256");
    // make_https_request_test("www.facebook.com", "/", "RSA SHA-256");
    // make_https_request_test("www.whatsapp.com", "/", "RSA SHA-256");
    // make_https_request_test("www.linkedin.com", "/", "RSA SHA-256");

    // make_https_request_test("catfact.ninja", "/fact", "ECDSA SHA-256");
    // make_https_request_test("www.wikipedia.org", "/", "ECDSA SHA-384");
    // make_https_request_test("scotthelme.co.uk", "/", "ECDSA SHA-384");
    // make_https_request_test("stackoverflow.com", "/", "ECDSA SHA-384");

    while (true) {
        sleep_ms(1000);
    }
}
