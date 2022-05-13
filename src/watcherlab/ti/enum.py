"""
枚举类型
"""


class IntelligenceType(object):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SM3 = "sm3"
    SKID = "skid"
    JA3 = "ja3"
    JA3S = "ja3s"


class IntelligenceOrigin(object):
    PUBLIC = "public"
    VENDOR = "vendor"
    DEVICE = "device"
    CUSTOM = "custom"


class CoreApiVersion(object):
    V2 = "v2"


class CloudApiVersion(object):
    V2 = "v2"


class CoreApiPath(object):
    LIMITS = "sys/apikey/limits"
    INTELLIGENCE_FEED = "intelligence/feed"
    INTELLIGENCE_TYPE = "intelligence/type"
    INTELLIGENCE_FEED_LIST = "intelligence/feed/list"
    INTELLIGENCE = "intelligence"


class CloudApiPath(object):
    LIMITS = "sys/apikey/limits"
    IP_AS = "ip/as"
    IP_GEO = "ip/geo"
    IP_WHOIS = "ip/whois"
    DOMAIN_WHOIS = "domain/whois"
    DOMAIN_RANK = "domain/rank"


class Risk(object):
    SECURE = 1
    UNKNOWN = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50


class Decision(object):
    RELEASE = 1
    SECURE = 2
    WATCHING = 20
    UNKNOWN = 11
    BLOCK = 30
    INSECURE = 31
    ALERT = 40
    ALERT_FIRST_CONTACTS = 41
    ALERT_SECOND_CONTACTS = 42
