#ifndef DNS_INCLUDED
#define DNS_INCLUDED

#include "lwip/dns.h"
#include "pico/cyw43_arch.h"

typedef struct DNS_STATE
{
  bool is_used;
  bool completed;
  err_t result;
  ip_addr_t ip_addr;
  const char *hostname;
} DNS_STATE_T;

DNS_STATE_T *dns_init_state(const char *hostname);
void dns_free_state(DNS_STATE_T *state);

err_t dns_resolve_async(DNS_STATE_T *state);
void dns_wait_for_resolve(DNS_STATE_T *state);
err_t dns_resolve_sync(DNS_STATE_T *state);

DNS_STATE_T dns_state = {0};

DNS_STATE_T *dns_init_state(const char *hostname)
{
  DNS_STATE_T *state = &dns_state;
  if (state->is_used)
  {
    panic("dns state already in use!");
  }
  memset(state, 0, sizeof(DNS_STATE_T));
  state->is_used = true;
  state->hostname = hostname;

  return state;
}

void dns_free_state(DNS_STATE_T *state)
{
  state->is_used = false;
}

void dns_resolve_found(const char *name, const ip_addr_t *ip_addr, void *arg)
{
  DNS_STATE_T *state = (DNS_STATE_T *)arg;
  state->completed = true;

  if (ip_addr)
  {
    state->result = ERR_OK;
    state->ip_addr.addr = ip_addr->addr;
  }
  else
  {
    state->result = ERR_VAL;
  }
}

err_t dns_resolve_async(DNS_STATE_T *state)
{
  cyw43_arch_lwip_begin();
  err_t err = dns_gethostbyname(state->hostname, &state->ip_addr, dns_resolve_found, state);
  cyw43_arch_lwip_end();

  if (err != ERR_INPROGRESS)
  {
    state->completed = true;
    state->result = err;
  }

  return err;
}

void dns_wait_for_resolve(DNS_STATE_T *state)
{
  async_context_t *context = cyw43_arch_async_context();

  while (!state->completed)
  {
    async_context_wait_for_work_ms(context, 100);
  }
}

err_t dns_resolve_sync(DNS_STATE_T *state)
{
  if (dns_resolve_async(state) == ERR_INPROGRESS)
  {
    dns_wait_for_resolve(state);
  }

  return state->result;
}

#endif