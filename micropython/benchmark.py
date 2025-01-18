import urequests
from time import ticks_ms
import gc


def make_request(url, cert):
    req_start_time = ticks_ms()
    try:
        res = urequests.get(url, headers={"Accept": "*/*", "User-Agent": "RaspberryPiPico/1.0 (lwIP; bare-metal)", "Connection": "Close"}, parse_headers=False, timeout=60)
        # this line reads whole body
        res.text
        res.close()
        print('Request to', url, 'SUCCEEDED in',
              ticks_ms() - req_start_time, "ms", "| cert:", cert)
        res = None
        gc.collect()
    except Exception as e:
        print('Request to', url, 'FAILED in',
              ticks_ms() - req_start_time, 'ms; exception:', e, "| cert: ", cert)


make_request("https://www.google.com/", "RSA SHA-256")
make_request("https://www.youtube.com/", "RSA SHA-256")
make_request("https://www.facebook.com/", "RSA SHA-256")
make_request("https://www.whatsapp.com/", "RSA SHA-256")
make_request("https://www.linkedin.com/", "RSA SHA-256")

make_request("https://catfact.ninja/fact", "ECDSA SHA-256")
make_request("https://www.wikipedia.org/", "ECDSA SHA-384")
make_request("https://scotthelme.co.uk/", "ECDSA SHA-384")
make_request("https://stackoverflow.com/", "ECDSA SHA-384")
