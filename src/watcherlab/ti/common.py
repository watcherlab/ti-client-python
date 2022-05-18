"""
通用类或者函数
"""

import hashlib
import time
from datetime import datetime

from watcherlab.ti.exception import SerializeError
from watcherlab.ti.enum import Risk, Decision


def md5sum(_blob: bytes) -> str:
    md5 = hashlib.md5()
    md5.update(_blob)
    return md5.hexdigest()


def sha1sum(_blob: bytes) -> str:
    sha1 = hashlib.sha1()
    sha1.update(_blob)
    return sha1.hexdigest()


class Serializer(object):
    __DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

    def __init__(self, _data: dict):
        self.__data = _data

    def value(self, _key: str):
        return self.__data[_key] if _key in self.__data else None

    def time(self, _key: str, _fmt: str = None) -> datetime:
        data = self.__data[_key]
        if data:
            # 尝试兼容Unix标准时间戳和精确到毫秒的时间戳
            if isinstance(data, int):
                if data / 1000000000000 > 1:
                    data = data / 1000
                return datetime.fromtimestamp(data)
            # 尝试兼容标准的字符串时间
            elif isinstance(data, str):
                fmt = _fmt if _fmt else self.__DATE_FORMAT
                return datetime.strptime(data, fmt)
        return None

    def bool(self, _key: str) -> bool:
        return bool(self.__data[_key])


class Hash(object):
    __TYPE = ["MD5", "SHA1", "SHA256", "SHA512", "SM3"]
    md5 = None
    sha1 = None
    sha256 = None
    sha512 = None
    sm3 = None

    def __init__(self, _data: dict):
        need = set(self.__TYPE)
        give = set([x.upper() for x in _data.keys()])
        if not need.intersection(give):
            raise SerializeError()

        data = Serializer(_data)
        self.md5 = data.value("md5")
        self.sha1 = data.value("sha1")
        self.sha256 = data.value("sha256")
        self.sha512 = data.value("sha512")
        self.sm3 = data.value("sm3")

    def __str__(self):
        return "{{MD5={0.md5}, SHA1={0.sha1}, SHA256={0.sha256}, SHA512={0.sha512}, SM3={0.sm3}}}".format(self)


class GeoIp(object):
    latitude = None
    longitude = None
    country_code = None
    country_name = None
    province_name = None
    city_name = None

    def __init__(self, _data: dict):
        data = Serializer(_data)
        self.latitude = data.value("latitude")
        self.longitude = data.value("longitude")
        self.country_code = data.value("country_code")
        self.country_name = data.value("country_name")
        self.province_name = data.value("province_name")
        self.city_name = data.value("city_name")

    def __str__(self):
        return "{{Latitude={0.latitude}, Longitude={0.longitude}, CountryCode={0.country_code}, " \
               "CountryName={0.country_name}, ProvinceName={0.province_name}, CityName={0.city_name}}}".format(self)


class AutonomousSystem(object):
    asn = 0
    cidr = None
    name = None

    def __init__(self, _data: dict):
        data = Serializer(_data)
        self.cidr = data.value("cidr")
        self.asn = data.value("asn")
        self.name = data.value("name")

    def __str__(self):
        return "{{ASN={0.asn}, CIDR={0.cidr}, Name={0.name}}}".format(self)


class ApiLimits(object):
    __MAX_SLEEP_TIME = 300
    __cycle_query_count = 0
    __cycle_start_time = datetime.now()
    version = None
    prefix = None
    path = None
    lpq = 0
    lpr = 0
    cycle = 0
    query = 0
    description = None

    def __init__(self, _data: dict):
        data = Serializer(_data)
        self.version = data.value("version")
        self.prefix = data.value("prefix")
        self.path = data.value("path")
        self.lpq = data.value("lpq")
        self.lpr = data.value("lpr")
        self.cycle = data.value("cycle")
        self.query = data.value("query")
        self.description = data.value("description")

        # TODO：临时策略将随着服务端修改而删除此策略，当path的第一个字符是正斜杠则删除这个字符
        if self.path[0] == '/':
            self.path = self.path[1:]

    def __str__(self):
        return "{{Version={0.version}, Prefix={0.prefix}, Path={0.path}, LPQ={0.lpq}, LPR={0.lpr}, Cycle={0.cycle}, " \
               "Query={0.query}, Description={0.description}}}".format(self)

    def pipeline(self):
        elapsed = (datetime.now() - self.__cycle_start_time).seconds

        # 距离上次请求以来已经经历了超过一个请求周期的时间
        # 此时将进入一个全新的请求周期
        if elapsed > self.cycle:
            self.__cycle_query_count = 1
            self.__cycle_start_time = datetime.now()
        elif self.__cycle_query_count >= self.query:
            # 如果自上次请求以来没有经历超过一个周期
            # 并且此时已经消耗了一个周期内允许的所有次数
            # 我们应当休眠一段时间以进入一个新的时间周期
            # 准确的休眠的时间应该是时间周期减去已经经历的时间
            # time.sleep(self.cycle - elapsed + 0.5)
            # 但由于多种原因无法设置的如此精准，我们设置为一个时间周期再加1秒
            time.sleep(min(self.cycle + 1, self.__MAX_SLEEP_TIME))
            self.__cycle_query_count = 1
            self.__cycle_start_time = datetime.now()
        else:
            # 如果不是上述的两种情况则说明距离上次请求之后还没有经历超过一个时间周期，但幸运的是我们还有请求次数可以使用
            # 我们需要消耗一个次数并允许此次请求
            self.__cycle_query_count += 1

        return True


class AccountLimits(object):
    __limits = {}

    def __init__(self, _data: list):
        limits = [ApiLimits(x) for x in _data]
        for i in limits:
            self.__limits[i.path] = i

    def __str__(self):
        return "{{ApiLimits={}}}".format(self.__limits)

    def limits(self, _path: str) -> ApiLimits:
        return self.__limits[_path] if _path in self.__limits else None

    def lpq(self, _path: str) -> int:
        limits = self.limits(_path)
        return limits.lpq if limits else 0

    def lpr(self, _path: str) -> int:
        limits = self.limits(_path)
        return limits.lpr if limits else 0

    def pipeline(self, _path: str):
        limits = self.limits(_path)
        return limits.pipeline() if limits else True


class RiskMapping(object):
    __MAPPING = {
        "安全": Risk.SECURE,
        "未知": Risk.UNKNOWN,
        "低风险": Risk.LOW,
        "中风险": Risk.MEDIUM,
        "高风险": Risk.HIGH,
        "关键风险": Risk.CRITICAL,
    }

    @staticmethod
    def get_code(_name: str) -> int:
        if _name in RiskMapping.__MAPPING:
            return RiskMapping.__MAPPING[_name]
        return 0

    @staticmethod
    def get_name(_code: int) -> str:
        for k, v in RiskMapping.__MAPPING.items():
            if v == _code:
                return k
        return None


class DecisionMapping(object):
    __MAPPING = {
        "放行": Decision.RELEASE,
        "安全": Decision.SECURE,
        "观察": Decision.WATCHING,
        "未知": Decision.UNKNOWN,
        "阻断": Decision.BLOCK,
        "不安全": Decision.INSECURE,
        "主动通知告警": Decision.ALERT,
        "通知首选联系人": Decision.ALERT_FIRST_CONTACTS,
        "通知备用联系人": Decision.ALERT_SECOND_CONTACTS,
    }

    @staticmethod
    def get_code(_name: str) -> int:
        if _name in DecisionMapping.__MAPPING:
            return DecisionMapping.__MAPPING[_name]
        return 0

    @staticmethod
    def get_name(_code: int) -> str:
        for k, v in DecisionMapping.__MAPPING.items():
            if v == _code:
                return k
        return None
