#include "tcp.c"

#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

typedef void (*tls_close_callback)(void *arg, err_t err);
typedef void (*tls_recv_callback)(void *arg, u8_t *buf, size_t len);
typedef void (*tls_connected_callback)(void *arg);

typedef struct TLS_CLIENT_STATE
{
  bool is_used;
  const char *hostname;

  int result;

  TCP_CLIENT_STATE_T *tcp_state;

  void *callback_arg;
  tls_close_callback on_close_callback;
  tls_recv_callback on_recv_callback;
  tls_connected_callback on_connected_callback;

  u8_t *payload;
  size_t payload_len;

  struct pbuf *p;
  u16_t p_bytes_read;

  u64_t handshake_start_time;
  u64_t handshake_end_time;

  bool finished_handshake;

  struct
  {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
  } mbedtls;
} TLS_CLIENT_STATE_T;

TLS_CLIENT_STATE_T tls_client_state = {0};

err_t tls_client_close(TLS_CLIENT_STATE_T *state)
{
  mbedtls_ssl_close_notify(&state->mbedtls.ssl);
  mbedtls_ssl_free(&state->mbedtls.ssl);
  mbedtls_ssl_config_free(&state->mbedtls.conf);
  mbedtls_ctr_drbg_free(&state->mbedtls.ctr_drbg);
  mbedtls_entropy_free(&state->mbedtls.entropy);

  return tcp_client_close(state->tcp_state);
}

int tls_client_send(TLS_CLIENT_STATE_T *state, void *data, u16_t len)
{
  int bytes_written = mbedtls_ssl_write(&state->mbedtls.ssl, data, len);

  if (bytes_written < 0)
  {
    tcp_client_close(state->tcp_state);
    printf("ERROR while sending tls data! %d\n", bytes_written);
    state->result = bytes_written;
    return bytes_written;
  }

  return bytes_written;
}

void tls_tcp_recv(void *arg, struct pbuf *p)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;

  if (state->finished_handshake)
  {
    char buf[2048];

    if (p->tot_len > 2048)
    {
      panic("Packet overflow!");
    }

    state->p = p;
    state->p_bytes_read = 0;

    int ret = 0;
    do
    {
      ret = mbedtls_ssl_read(&state->mbedtls.ssl, buf, 2048);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ && state->p_bytes_read < state->p->tot_len);

    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ)
    {
      state->result = ret;
      tls_client_close(state);
      return;
    }

    tcp_recved(state->tcp_state->pcb, p->tot_len);
    pbuf_free(p);

    return;
  }

  if (state->p)
  {
    panic("handshake packet already pending");
  }

  state->p = p;

  int ret = -1;

  while (state->p_bytes_read < p->tot_len && ret != 0)
  {
    ret = mbedtls_ssl_handshake(&state->mbedtls.ssl);
  }

  pbuf_free(state->p);
  tcp_recved(state->tcp_state->pcb, state->p->tot_len);

  state->p_bytes_read = 0;
  state->p = NULL;

  if (ret == 0)
  {
    state->handshake_end_time = time_us_64();
    state->finished_handshake = true;

    if (state->on_connected_callback)
    {
      state->on_connected_callback(state->callback_arg);
    }

    if (state->payload && state->payload_len)
    {
      tls_client_send(state, state->payload, state->payload_len);
    }
  }
}

void tls_tcp_close(void *arg, err_t err)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;
  state->result = err;

  if (state->on_close_callback)
  {
    state->on_close_callback(state->callback_arg, err);
  }
}

void tls_tcp_connected(void *arg)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;

  state->handshake_start_time = time_us_64();
  int result = mbedtls_ssl_handshake(&state->mbedtls.ssl);

  if (result != ERR_OK && result != MBEDTLS_ERR_SSL_WANT_READ)
  {
    state->result = result;
    printf("TLS handshake failed\n");
    tcp_client_close(state->tcp_state);
    return;
  }
}

void tls_client_free_state(TLS_CLIENT_STATE_T *state)
{
  tcp_client_free_state(state->tcp_state);
  state->is_used = false;

  mbedtls_ssl_close_notify(&state->mbedtls.ssl);

  mbedtls_ssl_free(&state->mbedtls.ssl);
  mbedtls_ssl_config_free(&state->mbedtls.conf);
  mbedtls_ctr_drbg_free(&state->mbedtls.ctr_drbg);
  mbedtls_entropy_free(&state->mbedtls.entropy);
}

int tls_mbedtls_recv(void *arg, u8_t *buf, size_t len)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;

  if (!state->p || state->p->tot_len <= state->p_bytes_read)
  {
    return MBEDTLS_ERR_SSL_WANT_READ;
  }

  u16_t bytes_read = pbuf_copy_partial(state->p, buf, len, state->p_bytes_read);
  state->p_bytes_read += bytes_read;

  return bytes_read;
}

int tls_mbedtls_send(void *arg, const u8_t *data, size_t len)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;
  state->result = tcp_client_send(state->tcp_state, (void *)data, len);

  return len;
}

err_t tls_client_open_connection(TLS_CLIENT_STATE_T *state)
{
  state->result = tcp_client_open_connection(state->tcp_state);

  if (state->result != ERR_OK)
  {
    printf("TCP connection failed!\n");

    return state->result;
  }

  return state->result;
}

TLS_CLIENT_STATE_T *tls_client_init_state(ip_addr_t *ip_addr, uint16_t port, const char *hostname)
{
  TLS_CLIENT_STATE_T *state = &tls_client_state;

  if (state->is_used)
  {
    panic("tls state already in use!");
  }
  memset(state, 0, sizeof(TLS_CLIENT_STATE_T));
  state->is_used = true;

  state->tcp_state = tcp_client_init_state(ip_addr, port);
  state->hostname = hostname;

  state->tcp_state->callback_arg = state;
  state->tcp_state->on_recv_callback = tls_tcp_recv;
  state->tcp_state->on_close_callback = tls_tcp_close;
  state->tcp_state->on_connected_callback = tls_tcp_connected;

  // mbedtls init

  mbedtls_ssl_init(&state->mbedtls.ssl);
  mbedtls_ssl_config_init(&state->mbedtls.conf);
  mbedtls_ctr_drbg_init(&state->mbedtls.ctr_drbg);
  mbedtls_entropy_init(&state->mbedtls.entropy);

  const char *pers = "embedded_tls_client";

  int ret = mbedtls_ctr_drbg_seed(&state->mbedtls.ctr_drbg, mbedtls_entropy_func, &state->mbedtls.entropy,
                                  (const unsigned char *)pers, strlen(pers));
  if (ret != 0)
  {
    printf("mbedtls_ctr_drbg_seed failed, error: -0x%04x\n", -ret);
  }

  ret = mbedtls_ssl_config_defaults(&state->mbedtls.conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0)
  {
    printf("mbedtls_ssl_config_defaults failed, error: -0x%04x\n", -ret);
  }

  mbedtls_ssl_conf_rng(&state->mbedtls.conf, mbedtls_ctr_drbg_random, &state->mbedtls.ctr_drbg);

  ret = mbedtls_ssl_setup(&state->mbedtls.ssl, &state->mbedtls.conf);
  if (ret != 0)
  {
    printf("mbedtls_ssl_setup failed, error: -0x%04x\n", -ret);
  }

  ret = mbedtls_ssl_set_hostname(&state->mbedtls.ssl, state->hostname);
  if (ret != 0)
  {
    printf("mbedtls_ssl_set_hostname failed, error: -0x%04x\n", -ret);
  }

  mbedtls_ssl_set_bio(&state->mbedtls.ssl, state, tls_mbedtls_send, tls_mbedtls_recv, NULL);
  mbedtls_ssl_conf_authmode(&state->mbedtls.conf, MBEDTLS_SSL_VERIFY_NONE);

  return state;
}