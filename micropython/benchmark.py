from urllib import urequest
from time import ticks_ms
import gc


def make_request(url):
    req_start_time = ticks_ms()
    try:
        req = urequest.urlopen(url)
        req.read()
        req.close()
        print('Request to', url, 'SUCCEEDED in',
              ticks_ms() - req_start_time, "ms")
        req = None
        gc.collect()
    except Exception as e:
        print('Request to', url, 'FAILED in',
              ticks_ms() - req_start_time, 'ms; exception:', e)


make_request("https://www.google.com/")
make_request("https://www.youtube.com/")
make_request("https://www.facebook.com/")
make_request("https://www.wikipedia.org")
make_request("https://catfact.ninja/fact")  # some random test api
