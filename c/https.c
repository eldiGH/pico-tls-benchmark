#include "tls.c"
#include "dns.c"
#include <string.h>
#include "http_utils.c"

#define HTTP_TIMEOUT_TIME_S 60

typedef struct HTTPS_STATE
{
  bool is_used;

  TLS_CLIENT_STATE_T *tls_state;
  DNS_STATE_T *dns_state;

  const char *hostname;
  const char *url;

  char payload[HTTP_PAYLOAD_MAX_SIZE];

  bool completed;
  int result;
} HTTPS_STATE_T;

HTTPS_STATE_T https_state = {0};

void https_on_recv(void *arg, u8_t *buf, size_t len)
{
  for (int i = 0; i < len; i++)
  {
    putchar(buf[i]);
  }
}

void https_on_connection_close(void *arg, int err)
{
  HTTPS_STATE_T *state = (HTTPS_STATE_T *)arg;

  state->completed = true;
  state->result = err;
}

HTTPS_STATE_T *https_init_state(const char *hostname, const char *url)
{
  HTTPS_STATE_T *state = &https_state;
  if (state->is_used)
  {
    panic("https state already in use!");
  }
  memset(state, 0, sizeof(HTTPS_STATE_T));
  state->is_used = true;

  state->hostname = hostname;
  state->url = url;

  state->dns_state = dns_init_state(hostname);
  state->tls_state = tls_client_init_state(NULL, 443, hostname);

  state->tls_state->callback_arg = state;
  state->tls_state->on_close_callback = https_on_connection_close;
  // state->tls_state->on_recv_callback = https_on_recv;

  return state;
}

void https_free_state(HTTPS_STATE_T *state)
{
  if (state->dns_state)
  {
    dns_free_state(state->dns_state);
    state->dns_state = NULL;
  }

  if (state->tls_state)
  {
    tls_client_free_state(state->tls_state);
    state->tls_state = NULL;
  }

  state->is_used = false;
}

int https_make_request_async(HTTPS_STATE_T *state)
{
  int err = dns_resolve_sync(state->dns_state);
  if (err != ERR_OK)
  {
    printf("Could not resolve hostname: %s err: %i\n", state->hostname, err);
    dns_free_state(state->dns_state);
    state->result = err;
    return err;
  }

  state->tls_state->tcp_state->ip_addr.addr = state->dns_state->ip_addr.addr;

  u32_t payload_len = http_get_request_payload(state->payload, state->hostname, state->url);

  state->tls_state->payload = state->payload;
  state->tls_state->payload_len = payload_len;
  state->tls_state->tcp_state->timeout_secs = HTTP_TIMEOUT_TIME_S;

  err = tls_client_open_connection(state->tls_state);

  if (err)
  {
    printf("Could not make connection to: %s err: %i\n", state->hostname, err);
    https_free_state(state);
    state->result = err;
    return err;
  }

  return ERR_OK;
}

void https_wait_for_request(HTTPS_STATE_T *state)
{
  async_context_t *context = cyw43_arch_async_context();

  while (!state->completed)
  {
    async_context_wait_for_work_ms(context, 100);
  }
}

int https_make_request_sync(HTTPS_STATE_T *state)
{
  int err = https_make_request_async(state);
  if (err)
  {
    return err;
  }
  https_wait_for_request(state);

  return state->result;
}