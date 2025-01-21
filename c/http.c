#include "tcp.c"
#include "dns.c"
#include <string.h>
#include "http_utils.c"

#define HTTP_TIMEOUT_TIME_S 60
#define MAX_HTTP_PAYLOAD

typedef struct HTTP_STATE
{
  bool is_used;

  TCP_CLIENT_STATE_T *tcp_state;
  DNS_STATE_T *dns_state;

  const char *hostname;
  const char *url;

  char payload[HTTP_PAYLOAD_MAX_SIZE];

  bool completed;
  err_t result;
} HTTP_STATE_T;

HTTP_STATE_T http_state = {0};

void http_on_connection_close(void *arg, err_t err)
{
  HTTP_STATE_T *state = (HTTP_STATE_T *)arg;

  state->completed = true;
  state->result = err;
}

HTTP_STATE_T *http_init_state(const char *hostname, const char *url)
{
  HTTP_STATE_T *state = &http_state;
  if (state->is_used)
  {
    panic("http state already in use!");
  }
  memset(state, 0, sizeof(HTTP_STATE_T));
  state->is_used = true;

  state->hostname = hostname;
  state->url = url;

  state->dns_state = dns_init_state(hostname);
  state->tcp_state = tcp_client_init_state(NULL, 80);

  state->tcp_state->callback_arg = state;
  state->tcp_state->on_close_callback = http_on_connection_close;

  return state;
}

void http_free_state(HTTP_STATE_T *state)
{
  if (state->dns_state)
  {
    dns_free_state(state->dns_state);
    state->dns_state = NULL;
  }

  if (state->tcp_state)
  {
    tcp_client_free_state(state->tcp_state);
    state->tcp_state = NULL;
  }

  state->is_used = false;
}

err_t http_make_request_async(HTTP_STATE_T *state)
{
  err_t err = dns_resolve_sync(state->dns_state);
  if (err != ERR_OK)
  {
    printf("Could not resolve hostname: %s err: %i\n", state->hostname, err);
    dns_free_state(state->dns_state);
    state->result = err;
    return err;
  }

  state->tcp_state->ip_addr.addr = state->dns_state->ip_addr.addr;

  u32_t payload_len = http_get_request_payload(state->payload, state->hostname, state->url);

  state->tcp_state->payload = state->payload;
  state->tcp_state->payload_len = payload_len;
  state->tcp_state->timeout_secs = HTTP_TIMEOUT_TIME_S;

  err = tcp_client_open_connection(state->tcp_state);

  if (err)
  {
    printf("Could not make connection to: %s err: %i\n", state->hostname, err);
    http_free_state(state);
    state->result = err;
    return err;
  }

  return ERR_OK;
}

void http_wait_for_request(HTTP_STATE_T *state)
{
  async_context_t *context = cyw43_arch_async_context();

  while (!state->completed)
  {
    async_context_wait_for_work_ms(context, 100);
  }
}

err_t http_make_request_sync(HTTP_STATE_T *state)
{
  err_t err = http_make_request_async(state);
  if (err)
  {
    return err;
  }
  http_wait_for_request(state);

  return state->result;
}

err_t http_make_simple_request_sync(const char *hostname, const char *url, bool parse_response)
{
  HTTP_STATE_T *state = http_init_state(hostname, url);

  err_t err = http_make_request_sync(state);

  http_free_state(state);

  return err;
}