from time import sleep_ms, ticks_ms
import network
import config

start_time = ticks_ms()

wlan = network.WLAN(network.STA_IF)

wlan.active(True)
wlan.connect(config.WIFI_SSID, config.WIFI_PASSWORD)

status = wlan.status()
while status > network.STAT_IDLE and status != network.STAT_GOT_IP:
    status = wlan.status()
    sleep_ms(1)

print("Connected in", ticks_ms() - start_time, "ms")
