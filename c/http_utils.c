#ifndef HTTP_UTILS_INCLUDED
#define HTTP_UTILS_INCLUDED
#define HTTP_PAYLOAD_MAX_SIZE 512

#define GET_REQUEST_TEMPLATE "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nUser-Agent: RaspberryPiPico/1.0 (lwIP; bare-metal)\r\nConnection: close\r\n\r\n"

uint32_t http_get_request_payload(char *buf, const char *hostname, const char *url)
{

  size_t payload_chars_count = snprintf(NULL, 0, GET_REQUEST_TEMPLATE, url, hostname);
  size_t payload_size = payload_chars_count + 1;

  if (payload_size > HTTP_PAYLOAD_MAX_SIZE)
  {
    panic("Http request payload greater than HTTP_PAYLOAD_MAX_SIZE=! calculated size=%u", HTTP_PAYLOAD_MAX_SIZE, payload_size);
  }

  return snprintf(buf, HTTP_PAYLOAD_MAX_SIZE, GET_REQUEST_TEMPLATE, url, hostname);
  ;
}
#endif