#ifndef TCP_INCLUDED
#define TCP_INCLUDED

#include "lwip/pbuf.h"
#include "lwip/tcp.h"

#include "pico/cyw43_arch.h"

#define TCP_CLIENT_STATE_POOL_SIZE 5

typedef void (*tcp_close_callback)(void *arg, err_t err);
typedef void (*tcp_recv_callback)(void *arg, struct pbuf *p);
typedef void (*tcp_connected_callback)(void *arg);

typedef struct TCP_CLIENT_STATE
{
  bool is_used;

  ip_addr_t ip_addr;
  uint16_t port;

  struct tcp_pcb *pcb;

  u64_t start_time;

  bool connected;
  bool completed;
  err_t result;

  u8_t timeout_secs;

  char *payload;
  u16_t payload_len;

  void *callback_arg;
  tcp_close_callback on_close_callback;
  tcp_recv_callback on_recv_callback;
  tcp_connected_callback on_connected_callback;

  u64_t tcp_connect_start_time;
  u64_t tcp_connect_end_time;

} TCP_CLIENT_STATE_T;

TCP_CLIENT_STATE_T tcp_client_state = {0};

TCP_CLIENT_STATE_T *
tcp_client_init_state(ip_addr_t *ip_addr, uint16_t port)
{
  TCP_CLIENT_STATE_T *state = &tcp_client_state;
  if (state->is_used)
  {
    panic("tcp state already in use!");
  }

  memset(state, 0, sizeof(TCP_CLIENT_STATE_T));
  state->is_used = true;

  if (ip_addr)
  {
    state->ip_addr.addr = ip_addr->addr;
  }
  state->port = port;

  state->timeout_secs = 60;

  return state;
}

void tcp_client_free_state(TCP_CLIENT_STATE_T *state)
{
  state->is_used = false;
}

err_t tcp_client_close(void *arg)
{
  TCP_CLIENT_STATE_T *state = (TCP_CLIENT_STATE_T *)arg;
  err_t err = ERR_OK;

  state->completed = true;
  state->connected = false;
  if (state->pcb == NULL)
  {
    return err;
  }

  tcp_arg(state->pcb, NULL);
  tcp_poll(state->pcb, NULL, 0);
  tcp_recv(state->pcb, NULL);
  tcp_err(state->pcb, NULL);

  err = tcp_close(state->pcb);

  if (err != ERR_OK)
  {
    printf("Could not close tcp connection! Aborting...\n");
    tcp_abort(state->pcb);
    err = ERR_ABRT;
  }

  state->pcb = NULL;

  if (state->on_close_callback)
  {
    state->on_close_callback(state->callback_arg, state->result);
  }

  return err;
}

err_t tcp_client_poll(void *arg, struct tcp_pcb *pcb)
{
  TCP_CLIENT_STATE_T *state = (TCP_CLIENT_STATE_T *)arg;

  uint64_t elapsed_time = time_us_64() - state->start_time;

  if (elapsed_time >= state->timeout_secs * 1000000)
  {
    state->result = ERR_TIMEOUT;
    return tcp_client_close(state);
  }

  return ERR_OK;
}

void tcp_client_err(void *arg, err_t err)
{
  TCP_CLIENT_STATE_T *state = (TCP_CLIENT_STATE_T *)arg;

  state->result = err;

  printf("TCP connection error! %i\n", err);
  tcp_client_close(state);

  return;
}

err_t tcp_client_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  TCP_CLIENT_STATE_T *state = (TCP_CLIENT_STATE_T *)arg;

  if (err != ERR_OK)
  {
    printf("RECV ERROR\n");
    state->result = err;

    if (p)
    {
      pbuf_free(p);
    }

    return tcp_client_close(state);
  }

  // Connection closed
  if (!p)
  {
    return tcp_client_close(state);
  }

  // Got some data to process
  if (p->tot_len > 0)
  {
    if (state->on_recv_callback)
    {
      state->on_recv_callback(state->callback_arg, p);
    }
    else
    {
      pbuf_free(p);
      tcp_recved(pcb, p->tot_len);
    }
  }

  return ERR_OK;
}

err_t tcp_client_send(TCP_CLIENT_STATE_T *state, void *data, u16_t len)
{
  state->result = tcp_write(state->pcb, data, len, TCP_WRITE_FLAG_COPY);
  if (state->result != ERR_OK)
  {
    printf("error writing data, err=%d", state->result);
    return tcp_client_close(state);
  }

  return ERR_OK;
}

err_t tcp_client_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
  TCP_CLIENT_STATE_T *state = (TCP_CLIENT_STATE_T *)arg;
  state->tcp_connect_end_time = time_us_64();

  if (err != ERR_OK)
  {
    printf("connection failed to ip %s with error: \n", ip4addr_ntoa(&state->ip_addr), err);
    state->result = err;
    return tcp_client_close(state);
  }

  if (state->on_connected_callback)
  {
    state->on_connected_callback(state->callback_arg);
  }

  if (state->payload && state->payload_len > 0)
  {
    tcp_client_send(state, state->payload, state->payload_len);
  }

  state->connected = true;

  return ERR_OK;
}

err_t tcp_client_open_connection(TCP_CLIENT_STATE_T *state)
{
  state->pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (!state->pcb)
  {
    panic("Could not create new tcp connection!");
  }

  tcp_arg(state->pcb, state);
  tcp_poll(state->pcb, tcp_client_poll, 1);
  tcp_recv(state->pcb, tcp_client_recv);
  tcp_err(state->pcb, tcp_client_err);

  state->start_time = time_us_64();

  cyw43_arch_lwip_begin();
  state->tcp_connect_start_time = time_us_64();
  err_t err = tcp_connect(state->pcb, &state->ip_addr, state->port, tcp_client_connected);
  cyw43_arch_lwip_end();

  if (err != ERR_OK)
  {
    fprintf(stderr, "error initiating connect, err=%d\n", err);
    tcp_client_close(state);
  }

  return err;
}

#endif