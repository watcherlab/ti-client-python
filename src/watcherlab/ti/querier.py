"""
威胁情报数据查询
"""

from watcherlab.ti.platform import Core
from watcherlab.ti.enum import IntelligenceType, IntelligenceOrigin
from watcherlab.ti.intelligence import (
    Intelligence,
    IntelligenceIp,
    IntelligenceDomain,
    IntelligenceUrl,
    IntelligenceEmail,
    IntelligenceFile
)


class Querier(object):
    __TYPE = {
        "IP": ["ip", "ipv4", "ipv6"],
        "DOMAIN": ["domain"],
        "EMAIL": ["email"],
        "URL": ["url"],
        "FILE": ["md5", "sha1", "sha256", "sha512", "sm3"]
    }

    def __init__(self, _core: Core, _type: IntelligenceType):
        self.__core = _core
        self.__type = _type

    def __query(self, _origin: IntelligenceOrigin, _data: tuple) -> dict:
        retval = {}
        result = self.__core.intelligence(_origin, self.__type, *_data)

        if result:
            for i in result:
                parsed = None

                if self.__type in self.__TYPE["IP"]:
                    parsed = IntelligenceIp(i)
                elif self.__type in self.__TYPE["DOMAIN"]:
                    parsed = IntelligenceDomain(i)
                elif self.__type in self.__TYPE["URL"]:
                    parsed = IntelligenceUrl(i)
                elif self.__type in self.__TYPE["EMAIL"]:
                    parsed = IntelligenceEmail(i)
                elif self.__type in self.__TYPE["FILE"]:
                    parsed = IntelligenceFile(i)

                if parsed:
                    retval[parsed.data] = parsed
        return retval

    def public(self, *_data: str) -> dict:
        return self.__query(IntelligenceOrigin.PUBLIC, _data)

    def vendor(self, *_data: str) -> dict:
        return self.__query(IntelligenceOrigin.VENDOR, _data)

    def custom(self, *_data: str) -> dict:
        return self.__query(IntelligenceOrigin.CUSTOM, _data)

    def device(self, *_data: str) -> dict:
        return self.__query(IntelligenceOrigin.DEVICE, _data)


class IpQuerier(Querier):
    def __init__(self, _core: Core):
        super(IpQuerier, self).__init__(_core, IntelligenceType.IP)


class DomainQuerier(Querier):
    def __init__(self, _core: Core):
        super(DomainQuerier, self).__init__(_core, IntelligenceType.DOMAIN)


class UrlQuerier(Querier):
    def __init__(self, _core: Core):
        super(UrlQuerier, self).__init__(_core, IntelligenceType.URL)


class EmailQuerier(Querier):
    def __init__(self, _core: Core):
        super(EmailQuerier, self).__init__(_core, IntelligenceType.EMAIL)


class MD5Querier(Querier):
    def __init__(self, _core: Core):
        super(MD5Querier, self).__init__(_core, IntelligenceType.MD5)


class SHA1Querier(Querier):
    def __init__(self, _core: Core):
        super(SHA1Querier, self).__init__(_core, IntelligenceType.SHA1)


class SHA256Querier(Querier):
    def __init__(self, _core: Core):
        super(SHA256Querier, self).__init__(_core, IntelligenceType.SHA256)


class SHA512Querier(Querier):
    def __init__(self, _core: Core):
        super(SHA512Querier, self).__init__(_core, IntelligenceType.SHA512)


class SM3Querier(Querier):
    def __init__(self, _core: Core):
        super(SM3Querier, self).__init__(_core, IntelligenceType.SM3)
