#include "tls.c"
#include "dns.c"
#include <string.h>

#define GET_REQUEST_TEMPLATE "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nUser-Agent: RaspberryPiPico/1.0 (lwIP; bare-metal)\r\nConnection: close\r\n\r\n"
#define HTTP_TIMEOUT_TIME_S 60

typedef struct HTTPS_STATE
{
  TLS_CLIENT_STATE_T *tls_state;
  DNS_STATE_T *dns_state;

  const char *hostname;
  const char *url;

  bool completed;
  err_t result;
} HTTPS_STATE_T;

void https_on_connection_close(void *arg, err_t err)
{
  HTTPS_STATE_T *state = (HTTPS_STATE_T *)arg;

  state->completed = true;
  state->result = err;
}

size_t size_t_clamp(size_t max, size_t value)
{
  if (value > max)
  {
    return max;
  }

  return value;
}

HTTPS_STATE_T *https_init_state(const char *hostname, const char *url)
{
  HTTPS_STATE_T *state = calloc(1, sizeof(HTTPS_STATE_T));

  if (!state)
  {
    panic("Could not initialize https_state!\n");
  }

  state->hostname = hostname;
  state->url = url;

  state->dns_state = dns_init_state(hostname);
  state->tls_state = tls_client_init_state(NULL, 443, hostname, NULL);

  state->tls_state->callback_arg = state;
  state->tls_state->on_close_callback = https_on_connection_close;

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

  free(state);
}

err_t https_make_request_async(HTTPS_STATE_T *state)
{
  err_t err = dns_resolve_sync(state->dns_state);
  if (err != ERR_OK)
  {
    printf("Could not resolve hostname: %s err: %i\n", state->hostname, err);
    dns_free_state(state->dns_state);
    state->result = err;
    return err;
  }

  size_t payload_chars_count = snprintf(NULL, 0, GET_REQUEST_TEMPLATE, state->url, state->hostname);
  size_t payload_size = payload_chars_count + 1;
  char *payload = malloc(payload_size);
  snprintf(payload, payload_size, GET_REQUEST_TEMPLATE, state->url, state->hostname);

  state->tls_state->ip_addr.addr = state->dns_state->ip_addr.addr;

  state->tls_state->payload = payload;
  state->tls_state->payload_len = payload_chars_count; // We do not want string termination character to be sent
  state->tls_state->timeout_secs = HTTP_TIMEOUT_TIME_S;

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

err_t https_make_request_sync(HTTPS_STATE_T *state)
{
  err_t err = https_make_request_async(state);
  if (err)
  {
    return err;
  }
  https_wait_for_request(state);

  return state->result;
}

err_t https_make_simple_request_sync(const char *hostname, const char *url, bool parse_response)
{
  HTTPS_STATE_T *state = https_init_state(hostname, url);

  err_t err = https_make_request_sync(state);

  https_free_state(state);

  return err;
}