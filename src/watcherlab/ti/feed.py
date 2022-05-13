"""
威胁情报订阅数据下载
"""

from datetime import datetime

from watcherlab.ti.enum import IntelligenceType, Decision
from watcherlab.ti.common import Serializer, RiskMapping, DecisionMapping
from watcherlab.ti.exception import SerializeError
from watcherlab.ti.platform import Core


class FeedListItem(object):
    tags = None
    name = None
    type = set()

    def __init__(self, _data: dict):
        root = Serializer(_data)

        self.tags = root.value("tags")
        self.name = root.value("name")
        self.type = set(root.value("type"))

    def __str__(self):
        return "{{Tag={0.tags}, Name={0.name}, Type={0.type}}}".format(self)


class FeedList(object):
    items: dict[int, FeedListItem] = dict()

    def __init__(self, _data: list):
        if not _data:
            raise SerializeError()
        for i in _data:
            item = FeedListItem(i)
            if item:
                self.items[item.tags] = item

    def __str__(self):
        return "{{FeedListItem={}}}".format(self.items)

    def have_tag(self, _tag_id: int) -> bool:
        return _tag_id in self.items

    def have_name(self, _tag_name: str) -> bool:
        for tag, item in self.items.items():
            if item.name == _tag_name:
                return True
        return False

    def have_type(self, _type: str):
        for tag, item in self.items.items():
            if _type in item.type:
                return True
        return False

    def get_tags(self) -> set[int]:
        return set(self.items.keys())

    def get_names(self) -> set[str]:
        retval = set()
        for tag, item in self.items.items():
            retval.add(item.name)
        return retval

    def get_types(self) -> set[str]:
        retval = set()
        for tag, item in self.items.items():
            retval.update(item.type)
        return retval


class FeedItem(object):
    data = None
    type = None
    confidence = None
    decision = None
    inevent = False
    update_time = None
    risk = None

    def __init__(self, _data: dict):
        root = Serializer(_data)

        self.data = root.value("data")
        self.type = root.value("type")
        self.confidence = root.value("confidence")
        self.decision = root.value("decision")
        self.inevent = root.bool("inevent")
        self.update_time = root.time("updateDate")
        self.risk = root.value("risk")

    def __str__(self):
        return "{{Data={0.data}, Type={0.type}, Confidence={0.confidence}, Decision={0.decision}, " \
               "InEvent={0.inevent}, UpdateTime={0.update_time}, Risk={0.risk}}}".format(self)

    def get_risk_name(self) -> str | None:
        return RiskMapping.get_name(self.risk)

    def get_decision_name(self) -> str | None:
        return DecisionMapping.get_name(self.decision)


class Feed(object):
    __TIMEOUT = 3600

    def __init__(self, _core: Core):
        self.__core = _core
        self.__list = None
        self.__screen = None

    def __make__list(self):
        result = self.__core.feed_list()
        if result:
            self.__list = FeedList(result)
            self.__screen = datetime.now()

    def list(self) -> FeedList:
        if not self.__list:
            self.__make__list()

        elapsed = (datetime.now() - self.__screen).seconds
        if elapsed > self.__TIMEOUT:
            self.__make__list()

        return self.__list

    def download(self,
                 *_tags: int,
                 _limits: int = 100,
                 _confidence: int = 50,
                 _decision: Decision | None = None,
                 _inevent: bool | None = None,
                 _type: IntelligenceType = None) -> dict[str, FeedItem]:
        retval: dict[str, FeedItem] = dict()
        result = self.__core.feed_download(_tags, _limits, _confidence, _decision, _inevent, _type)
        for i in result:
            item = FeedItem(i)
            if item:
                retval[item.data] = item
        return retval
