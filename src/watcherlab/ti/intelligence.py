"""
威胁情报数据
"""

from watcherlab.ti.common import Serializer, GeoIp, AutonomousSystem, Hash, RiskMapping, DecisionMapping
from watcherlab.ti.exception import SerializeError, SerializeTypeError
from watcherlab.ti.platform import Cloud


class Properties(object):
    idc = None
    private = None
    boogon = None
    dynamic = None
    edu = None
    spider = None
    cdn = None
    dns = None
    satellite = None
    mobile = None
    sinkhole = None
    proxy_vpn = None
    proxy_http = None
    proxy_https = None
    proxy_socks = None
    proxy_tor = None
    proxy_tor_out = None

    def __init__(self, _data: dict):
        pass


class Record(object):
    __TMP_POLICY = "未知标签"
    __name = None
    category = None
    class__ = None
    time = None
    confidence = 0
    decision = 0
    risk = 0
    description = None

    def __init__(self, _data: dict):
        root = Serializer(_data)
        self.__name = root.value("name")
        self.category = root.value("category")
        self.class__ = root.value("class")
        self.time = root.time("time")
        self.confidence = root.value("confidence")
        self.description = root.value("description")
        self.risk = RiskMapping.get_code(root.value("risk"))
        self.decision = DecisionMapping.get_code(root.value("decision"))

    def __str__(self):
        return "{{Name={0.name}, Category={0.category}, Class={0.class__}, Time={0.time}, Risk={0.risk}, " \
               "Confidence={0.confidence}, Decision={0.decision}, Description={0.description}}}".format(self)

    @property
    def name(self) -> str | None:
        return self.description if self.__name == self.__TMP_POLICY else self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    def get_risk_name(self) -> str | None:
        return RiskMapping.get_name(self.risk)

    def get_decision_name(self) -> str | None:
        return DecisionMapping.get_name(self.decision)


class Origin(object):
    origin = None
    category = None
    class__ = None
    first_record = None
    last_record = None
    counter = None
    record = None

    def __init__(self, _data: dict):
        root = Serializer(_data)
        self.origin = root.value("origin")
        self.category = root.value("category")
        self.class__ = root.value("class")
        self.first_record = root.time("first_record")
        self.last_record = root.time("last_record")
        self.counter = root.value("counter")

        record = root.value("record")
        if record:
            self.record = [Record(x) for x in record]

    def __str__(self):
        return "{{Origin={0.origin}, Category={0.category}, Class={0.class__}, FirstRecord={0.first_record}, " \
               "LastRecord={0.last_record}, Counter={0.counter}, Record={0.record}}}".format(self)

    def get_tags(self) -> set:
        retval = set()
        if self.record:
            [retval.add(x.name) for x in self.record]
        return retval

    def get_risk_maximum(self) -> int:
        if self.record:
            risk_list = []
            [risk_list.append(x.risk) for x in self.record]
            return max(risk_list)
        return 0

    def get_risk_maximum_name(self) -> str | None:
        risk = self.get_risk_maximum()
        return RiskMapping.get_name(risk) if risk else None

    def get_decision_maximum(self) -> int:
        if self.record:
            decision_list = []
            [decision_list.append(x.decision) for x in self.record]
            return max(decision_list)
        return 0

    def get_decision_maximum_name(self) -> str | None:
        decision = self.get_decision_maximum()
        return DecisionMapping.get_name(decision) if decision else None


class Intelligence(object):
    __TYPE = []
    data = None
    type = None
    first_time = None
    life_cycle = None
    intelligence = None
    properties = None

    def __init__(self, _data: dict):
        self.__check(_data)

        root = Serializer(_data)
        self.data = root.value("query")
        self.type = root.value("type")

        data = Serializer(root.value("data"))
        self.first_time = data.time("first_time")
        self.life_cycle = data.value("life_cycle")

        intelligence = data.value("intelligence")
        if intelligence:
            self.intelligence = [Origin(x) for x in intelligence]

        properties = data.value("properties")
        if properties:
            self.properties = [Properties(x) for x in properties]

    def __str__(self):
        return "{{Data={0.data}, Type={0.type}, FirstTime={0.first_time}, LifeCycle={0.life_cycle}, " \
               "Intelligence={0.intelligence}, Properties={0.properties}}}".format(self)

    @classmethod
    def __check(cls, _data: dict):
        if "query" not in _data or "type" not in _data:
            raise SerializeError()

        if cls.__TYPE and _data["type"].upper() not in cls.__TYPE:
            raise SerializeTypeError(_data, cls.__TYPE)

    def get_tags(self) -> set:
        retval = set()
        if self.intelligence:
            [retval.update(x.get_tags()) for x in self.intelligence]
        return retval

    def get_risk_maximum(self) -> int:
        if self.intelligence:
            risk_list = []
            [risk_list.append(x.get_risk_maximum()) for x in self.intelligence]
            return max(risk_list)
        return 0

    def get_risk_maximum_name(self) -> str | None:
        risk = self.get_risk_maximum()
        return RiskMapping.get_name(risk) if risk else None

    def get_decision_maximum(self) -> int:
        if self.intelligence:
            decision_list = []
            [decision_list.append(x.get_decision_maximum()) for x in self.intelligence]
            return max(decision_list)
        return 0

    def get_decision_maximum_name(self) -> str | None:
        decision = self.get_decision_maximum()
        return DecisionMapping.get_name(decision) if decision else None


class IntelligenceIp(Intelligence):
    __TYPE = ["IP", "IPV4", "IPV6"]
    __as = None
    __geoip = None
    __whois = None
    certificate = None

    def __init__(self, _data: dict):
        super(IntelligenceIp, self).__init__(_data)

    def __str__(self):
        return "{{Intelligence={}, Certificate={}}}".format(super(IntelligenceIp, self).__str__(), self.certificate)

    @staticmethod
    def __index_zero(_response: list | None, _key: str):
        return _response[0][_key] if _response and _key in _response[0] else None

    def geo(self, _cloud: Cloud) -> GeoIp | None:
        data = self.__index_zero(_cloud.ip_geo(self.data), "data")
        return GeoIp(data) if data else None

    def whois(self, _cloud: Cloud) -> str | None:
        return self.__index_zero(_cloud.ip_whois(self.data), "data")

    def autonomous_system(self, _cloud: Cloud) -> list[AutonomousSystem]:
        data = self.__index_zero(_cloud.ip_as(self.data), "data")
        if data:
            return [AutonomousSystem(x) for x in data]
        return []


class IntelligenceDomain(Intelligence):
    __TYPE = ["DOMAIN"]
    __whois = None
    certificate = None

    def __init__(self, _data: dict):
        super(IntelligenceDomain, self).__init__(_data)

    def __str__(self):
        return "{{Intelligence={}, Certificate={}}}".format(super(IntelligenceDomain, self).__str__(), self.certificate)

    @staticmethod
    def __index_zero(_response: list | None, _key: str):
        return _response[0][_key] if _response and _key in _response[0] else None

    # def whois(self, _cloud: Cloud) -> str:
    #     return self.__index_zero(_cloud.domain_whois(self.data), "data")
    #
    # def rank(self, _cloud: Cloud) -> int:
    #     return self.__index_zero(_cloud.domain_rank(self.data), "rank")


class IntelligenceEmail(IntelligenceDomain):
    __TYPE = ["EMAIL"]

    def __init__(self, _data: dict):
        super(IntelligenceEmail, self).__init__(_data)

    def __str__(self):
        return super(IntelligenceEmail, self).__str__()


class IntelligenceUrl(IntelligenceDomain):
    __TYPE = ["URL"]

    def __init__(self, _data: dict):
        super(IntelligenceUrl, self).__init__(_data)

    def __str__(self):
        return super(IntelligenceUrl, self).__str__()


class IntelligenceFile(Intelligence):
    __TYPE = ["MD5", "SHA1", "SHA256", "SHA512", "SM3"]
    hash = None
    mime_type = None
    malware_family = None
    size = None
    downloadable = False

    def __init__(self, _data: dict):
        super(IntelligenceFile, self).__init__(_data)

        root = Serializer(_data)
        self.mime_type = root.value("mime_type")
        self.malware_family = root.value("malware_family")
        self.size = root.value("size")
        self.downloadable = root.value("downloadable")

        hash = root.value("hash")
        if hash:
            self.hash = Hash(hash)

    def __str__(self):
        return "{{Hash={0.hash}, MimeType={0.mime_type}, MalwareFamily={0.malware_family}, Size={0.size}, " \
               "Downloadable={0.downloadable}}}".format(self)
