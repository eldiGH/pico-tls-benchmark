#include "lwip/altcp_tls.h"
#include "pico/cyw43_arch.h"

typedef void (*tls_close_fn)(void *arg, err_t err);
typedef void (*tls_recv_fn)(void *arg, struct pbuf *p);

typedef struct TLS_CLIENT_STATE
{
  ip_addr_t ip_addr;
  uint16_t port;

  struct altcp_pcb *pcb;
  struct altcp_tls_config *tls_config;

  u64_t start_time;

  bool completed;
  err_t result;

  u8_t timeout_secs;

  const char *hostname;

  char *payload;
  u16_t payload_len;

  void *callback_arg;
  tls_close_fn on_close_callback;
  tls_recv_fn on_recv_callback;

} TLS_CLIENT_STATE_T;

static struct altcp_tls_config *default_tls_config = NULL;

/***
 * tls_config can be null, it will be defaulted to no cert.
 */
TLS_CLIENT_STATE_T *tls_client_init_state(ip_addr_t *ip_addr, uint16_t port, const char *hostname, struct altcp_tls_config *tls_config)
{
  TLS_CLIENT_STATE_T *state = calloc(1, sizeof(TLS_CLIENT_STATE_T));
  if (!state)
  {
    panic("Could not initialize tls_client_state!\n");
  }

  if (ip_addr)
  {
    state->ip_addr.addr = ip_addr->addr;
  }
  state->port = port;

  if (!tls_config)
  {
    if (!default_tls_config)
    {
      default_tls_config = altcp_tls_create_config_client(NULL, 0);
    }

    state->tls_config = default_tls_config;
  }
  else
  {
    state->tls_config = tls_config;
  }

  state->timeout_secs = 60;

  if (hostname)
  {
    state->hostname = hostname;
  }

  return state;
}

void tls_client_free_state(TLS_CLIENT_STATE_T *state)
{
  free(state);
}

err_t tls_client_close(void *arg)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;
  err_t err = ERR_OK;

  state->completed = true;
  if (state->pcb == NULL)
  {
    return err;
  }

  altcp_arg(state->pcb, NULL);
  altcp_poll(state->pcb, NULL, 0);
  altcp_recv(state->pcb, NULL);
  altcp_err(state->pcb, NULL);

  err = altcp_close(state->pcb);

  if (err != ERR_OK)
  {
    printf("Could not close tls connection! Aborting...\n");
    altcp_abort(state->pcb);
    err = ERR_ABRT;
  }

  state->pcb = NULL;

  if (state->on_close_callback)
  {
    state->on_close_callback(state->callback_arg, state->result);
  }

  return err;
}

err_t tls_client_poll(void *arg, struct altcp_pcb *pcb)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;

  uint64_t elapsed_time = time_us_64() - state->start_time;

  if (elapsed_time >= state->timeout_secs * 1000000)
  {
    state->result = ERR_TIMEOUT;
    return tls_client_close(state);
  }

  return ERR_OK;
}

void tls_client_err(void *arg, err_t err)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;

  printf("TLS connection error! %i\n", err);
  tls_client_close(state);

  state->result = err;
  return;
}

int packet_no = 1;

bool switch_buf = false;

err_t tls_client_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;

  if (err != ERR_OK)
  {
    printf("RECV ERROR\n");
    state->result = err;

    if (p)
    {
      pbuf_free(p);
    }

    return tls_client_close(state);
  }

  // Connection closed
  if (!p)
  {
    return tls_client_close(state);
  }

  // Got some data to process
  if (p->tot_len > 0)
  {
    if (state->on_recv_callback)
    {
      state->on_recv_callback(state->callback_arg, p);
    }
    altcp_recved(pcb, p->tot_len);
  }
  pbuf_free(p);

  return ERR_OK;
}

err_t tls_client_send(TLS_CLIENT_STATE_T *state, void *data, u16_t len)
{
  err_t err = altcp_write(state->pcb, data, len, TCP_WRITE_FLAG_COPY);
  if (err != ERR_OK)
  {
    printf("error writing data, err=%d", err);
    return tls_client_close(state);
  }

  return ERR_OK;
}

err_t tls_client_connected(void *arg, struct altcp_pcb *pcb, err_t err)
{
  TLS_CLIENT_STATE_T *state = (TLS_CLIENT_STATE_T *)arg;

  if (err != ERR_OK)
  {
    printf("connection failed to %s with error: \n", state->hostname, err);
    return tls_client_close(state);
  }

  if (state->payload && state->payload_len > 0)
  {
    tls_client_send(state, state->payload, state->payload_len);
  }

  return ERR_OK;
}

err_t tls_client_open_connection(TLS_CLIENT_STATE_T *state)
{
  state->pcb = altcp_tls_new(state->tls_config, IPADDR_TYPE_ANY);
  if (!state->pcb)
  {
    panic("Could not create new tls connection!");
  }

  altcp_arg(state->pcb, state);
  altcp_poll(state->pcb, tls_client_poll, 1);
  altcp_recv(state->pcb, tls_client_recv);
  altcp_err(state->pcb, tls_client_err);

  err_t err = mbedtls_ssl_set_hostname(altcp_tls_context(state->pcb), state->hostname);
  if (err != ERR_OK)
  {
    panic("Could not set mbedtls hostname!\n");
  }

  state->start_time = time_us_64();

  cyw43_arch_lwip_begin();
  err = altcp_connect(state->pcb, &state->ip_addr, state->port, tls_client_connected);
  cyw43_arch_lwip_end();

  if (err != ERR_OK)
  {
    fprintf(stderr, "error initiating connect, err=%d\n", err);
    tls_client_close(state);
  }

  return err;
}