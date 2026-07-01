"""
fingerprint.py — best-effort device-type classification (no hallucination).

Combines three *real* signals — the OUI vendor, open ports/services (from nmap),
and the hostname — into a coarse device type (Router / Phone / Printer / Camera
/ Media-TV / NAS / Computer / IoT / Smart-home). This is explicitly a heuristic
*triage label* to give the operator the "Angry IP / Fing" experience; it is
never presented as nmap's authoritative `-O` OS fingerprint. When no signal is
strong enough it returns "" (the UI shows nothing rather than a guess).

Every rule is driven by observed data, so the label is reproducible and
explainable — important for a security write-up.
"""

from __future__ import annotations

# --- open-port signatures: a signature matches when ALL its ports are open. -- #
# Ordered strongest-first; the first match wins. Post-nmap, this is the most
# reliable signal.
_PORT_SIGNATURES: list[tuple[set[int], str]] = [
    ({9100}, "Printer"),               # HP JetDirect raw printing
    ({631}, "Printer"),                # IPP
    ({515}, "Printer"),                # LPD
    ({554}, "Camera"),                 # RTSP
    ({37777}, "Camera"),               # Dahua
    ({32400}, "Media / TV"),           # Plex
    ({8009}, "Media / TV"),            # Chromecast
    ({5000, 548}, "NAS / Storage"),    # Synology DSM + AFP
    ({3389}, "Computer"),              # Windows RDP
    ({445, 139}, "Computer"),          # Windows SMB
    ({53, 80}, "Router / Gateway"),    # DNS + web admin (home gateway)
    ({22}, "Server / Computer"),       # SSH
]

# --- service-name keywords (substring match on the service label). ----------- #
_SERVICE_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("ipp", "jetdirect", "printer", "pdl-datastream", "hp-pdl"), "Printer"),
    (("rtsp", "onvif"), "Camera"),
    (("airplay", "plex", "dlna", "mediaserver", "spotify", "chromecast"), "Media / TV"),
    (("ms-wbt-server", "microsoft-ds", "netbios-ssn"), "Computer"),
    (("dnsmasq",), "Router / Gateway"),
]

# --- vendor keywords (substring match on the OUI vendor, lowercased). -------- #
_VENDOR_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("sagemcom", "technicolor", "arcadyan", "mikrotik", "mikrotikls", "routerboard",
      "ubiquiti", "netgear", "tp-link", "tp link", "d-link", "asustek", "zyxel",
      "arris", "fritz", "avm", "icotera", "cisco", "juniper", "aruba", "draytek",
      "ruckus", "fortinet", "sercomm", "askey", "actiontec", "calix", "adtran",
      "fiberhome", "tenda", "engenius", "edgecore", "commscope", "cambium",
      "meraki", "sophos", "watchguard", "palo alto", "sonicwall",
      "peplink"), "Router / Gateway"),
    (("hangzhou hikvision", "dahua", "reolink", "ring", "wyze", "amcrest",
      "axis comm", "hanwha", "ezviz", "uniview", "vivotek", "foscam", "swann",
      "lorex", "xiongmai", "mobotix", "geovision", "annke"), "Camera"),
    (("brother", "canon", "epson", "hewlett", "lexmark", "kyocera", "xerox",
      "ricoh", "oki data", "konica minolta", "sharp", "pantum", "zebra tech",
      "seiko epson", "toshiba tec"), "Printer"),
    (("synology", "qnap", "western digital", "seagate", "buffalo", "asustor",
      "terra master", "terramaster", "drobo", "netapp"), "NAS / Storage"),
    (("sonos", "roku", "vestel", "tcl", "vizio", "nvidia", "sony interactive",
      "harman", "hisense", "skyworth", "bose", "denon", "marantz", "yamaha",
      "humax"), "Media / TV"),
    (("hive", "nest", "ecobee", "signify", "philips lighting", "belkin", "wemo",
      "shelly", "sonoff", "tuya", "lifx", "lutron", "sengled", "yeelight",
      "leviton", "ikea of sweden", "resideo", "sonoff", "meross", "aqara",
      "wiz connected"), "Smart-home"),
    (("espressif", "raspberry", "texas instruments", "murata", "nordic",
      "particle", "fn-link", "azurewave", "altobeam", "ai-thinker",
      "hi-flying", "tuya smart", "seeed", "arduino", "u-blox", "silicon lab",
      "silicon laboratories", "gl technologies"), "IoT / Embedded"),
    (("apple",), "Apple device"),
    (("samsung", "xiaomi", "oneplus", "vivo", "oppo", "honor", "huawei",
      "nothing", "motorola", "realme", "google", "transsion", "sony mobile",
      "fairphone", "guangdong oppo"), "Phone / Tablet"),
    (("intel", "dell", "lenovo", "micro-star", "gigabyte", "liteon",
      "framework", "hewlett packard", "acer", "razer", "asrock", "supermicro",
      "fujitsu", "wistron", "compal", "quanta", "pegatron", "clevo",
      "tongfang", "vmware", "parallels", "virtualbox", "xensource",
      "qemu"), "Computer"),
]

# --- hostname keywords (substring match on a lowercased hostname). ----------- #
_HOSTNAME_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("router", "gateway", "gw", "openwrt", "fritz"), "Router / Gateway"),
    (("printer", "print", "officejet", "laserjet"), "Printer"),
    (("cam", "ipcam", "camera", "doorbell"), "Camera"),
    (("tv", "roku", "firetv", "appletv", "chromecast", "shield"), "Media / TV"),
    (("echo", "alexa", "nest", "hue", "hive"), "Smart-home"),
    (("nas", "synology", "diskstation", "qnap"), "NAS / Storage"),
    (("iphone", "ipad", "android", "phone", "pixel", "galaxy"), "Phone / Tablet"),
    # Windows / desktop / laptop self-assigned names. NB: Windows' default machine
    # name is "DESKTOP-XXXXXXX" and many corporate images use "WnnN-…"/asset tags,
    # so these are a strong, device-declared "this is a computer" signal.
    (("macbook", "imac", "desktop", "laptop", "pc-", "-pc", "thinkpad", "latitude",
      "elitebook", "probook", "optiplex", "precision", "surface", "w11", "w10",
      "win-", "wks", "workstation"), "Computer"),
]

# Modern phones/laptops use a randomized ("locally-administered") MAC for privacy.
RANDOM_MAC_LABEL = "(private/random)"


def _match_keywords(text: str | None, table) -> str | None:
    if not text:
        return None
    low = text.lower()
    for keywords, label in table:
        if any(k in low for k in keywords):
            return label
    return None


def guess_device_type(
    vendor: str | None = None,
    hostname: str | None = None,
    ports: list[int] | None = None,
    services: list[str] | None = None,
) -> str:
    """Return a coarse device-type label, or "" when no signal is strong enough.

    Priority: open-port signatures > service names > **hostname** > OUI vendor >
    randomized-MAC hint. Observed evidence (ports/services) comes first; then the
    device's *self-assigned hostname* — which is a stronger identity signal than
    the OUI vendor, because the OUI often names a sub-component (e.g. the Wi-Fi
    module: AzureWave/Intel/InProComm) rather than the product. That ordering is
    what stops a Windows "DESKTOP-…" laptop being mislabelled "IoT" just because
    its wireless card is made by an IoT-adjacent vendor. Returns "" when nothing
    is strong enough — we never guess.
    """
    open_ports = set(ports or [])

    # 1) open-port signatures (strongest — requires a completed nmap scan)
    for sig, label in _PORT_SIGNATURES:
        if sig <= open_ports:
            return label

    # 2) service names
    for svc in services or []:
        hit = _match_keywords(svc, _SERVICE_HINTS)
        if hit:
            return hit

    # 3) hostname (device's own name — beats the OUI of a sub-component vendor)
    hit = _match_keywords(hostname, _HOSTNAME_HINTS)
    if hit:
        return hit

    # 4) OUI vendor
    if vendor and vendor != RANDOM_MAC_LABEL:
        hit = _match_keywords(vendor, _VENDOR_HINTS)
        if hit:
            return hit

    # 5) a randomized MAC with no other signal is almost always a modern
    #    phone/laptop using a private Wi-Fi address — a useful, honest hint.
    if vendor == RANDOM_MAC_LABEL:
        return "Phone / Laptop"

    return ""
