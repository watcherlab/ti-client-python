"""
威胁情报平台
"""

import json
from http.client import HTTPResponse
from urllib.request import Request, urlopen

from watcherlab.__about__ import __author__
from watcherlab.enum import Locale

from watcherlab.ti.__about__ import __url__, __version__
from watcherlab.ti.exception import PlatformError, PlatformResponseError
from watcherlab.ti.common import AccountLimits
from watcherlab.ti.enum import (
    CoreApiVersion,
    CloudApiVersion,
    CoreApiPath,
    CloudApiPath,
    IntelligenceOrigin,
    IntelligenceType,
    Decision,
)


class Base(object):
    __USER_AGENT = __author__ + "ti/client/python"
    __CONTENT_TYPE = "application/json"
    __APIKEY = "X-WatcherLab-ApiKey"
    __ENCODING = "UTF-8"
    __RESPONSE = ["code", "msg", "data"]

    def __init__(self, _apikey: str, _host: str, _version: str = __version__, _timeout: int = 300):
        self.__apikey = _apikey
        self.__host = _host
        self.__version = _version
        self.__timeout = _timeout

    def request(self, _path: str, _parm: dict = None) -> HTTPResponse:
        url = "/".join([self.__host, _path])
        parm = bytes(json.dumps(_parm), encoding=self.__ENCODING) if _parm else None
        headers = {
            "User-Agent": "/".join([self.__USER_AGENT, self.__version]),
            "Content-Type": self.__CONTENT_TYPE,
            self.__APIKEY: self.__apikey
        }

        request = Request(url=url, headers=headers, data=parm)
        return urlopen(request, timeout=self.__timeout)

    def query(self, _path: str, _parm: dict = None) -> list:
        retval = []
        response = self.request(_path, _parm)

        try:
            if response.getcode() == 200:
                content = response.read().decode(self.__ENCODING)  # {"code":0,"msg":"success","data":[XXXX]}
                payload = json.loads(content)

                for k in self.__RESPONSE:
                    if k not in payload:
                        raise PlatformError("HTTP Api response illegal content")
                if payload["code"] != 0:
                    raise PlatformResponseError(payload)
                retval = payload["data"]
        except Exception as e:
            raise e
        finally:
            response.close()

        return retval

    def download(self, _path: str, _parm: dict = None) -> bytes | None:
        retval = None
        response = self.request(_path, _parm)

        try:
            if response.getcode() == 200:
                retval = response.read()
        except Exception as e:
            raise e
        finally:
            response.close()

        return retval


class Core(Base):
    __PATH_PREFIX = "core/api"

    def __init__(self,
                 _apikey: str,
                 _apiver: CoreApiVersion = CoreApiVersion.V2,
                 _pipeline: bool = False,
                 _host: str = __url__,
                 _local: Locale = Locale.ZH_CN):
        super(Core, self).__init__(_apikey, _host)
        self.__apiver = _apiver
        self.__pipeline = _pipeline
        self.__locale = _local
        self.__limits = None

    def __make_path(self, *_path) -> str:
        path = [self.__PATH_PREFIX, self.__apiver]
        path.extend(_path)
        return "/".join(path)

    def __make_parm(self, _parm: tuple) -> dict:
        return {"query": [x for x in _parm], "locale": self.__locale}

    def __make_feed_parm(self, _tags: tuple[int], _limits, _confidence, _decision, _inevent):
        retval = {"query": {"tags": [x for x in _tags], "limits": _limits, "confidence": _confidence},
                  "locale": self.__locale}

        if _decision:
            retval["query"]["decision"] = _decision

        if _inevent:
            retval["query"]["inevent"] = _inevent

        return retval

    def __make_limits(self):
        if not self.__limits:
            path = self.__make_path(CoreApiPath.LIMITS)
            limits = self.query(path)
            self.__limits = AccountLimits(limits)

    def __into_pipeline(self, _path: str):
        if self.__pipeline:
            self.__make_limits()
            return self.__limits.pipeline(_path)
        return True

    def datatype(self, *_data: str) -> list:
        path = CoreApiPath.INTELLIGENCE_TYPE
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(_data))

    def intelligence(self, _origin: IntelligenceOrigin, _type: IntelligenceType, *_data: str) -> list:
        path = "/".join([CoreApiPath.INTELLIGENCE, _origin, _type])
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(_data))

    def feed_list(self):
        path = CoreApiPath.INTELLIGENCE_FEED_LIST
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(("__MAKE_POST__",)))

    def feed_download(self,
                      _tags: tuple[int],
                      _limits: int = 100,
                      _confidence: int = 50,
                      _decision: Decision | None = None,
                      _inevent: bool | None = None,
                      _type: IntelligenceType = None):
        path = "/".join([CoreApiPath.INTELLIGENCE_FEED, _type]) if _type else CoreApiPath.INTELLIGENCE_FEED
        self.__into_pipeline(path)
        return self.query(self.__make_path(path),
                          self.__make_feed_parm(_tags, _limits, _confidence, _decision, _inevent))


class Cloud(Base):
    __PATH_PREFIX = "cloud/api"

    def __init__(self,
                 _apikey: str,
                 _apiver: CloudApiVersion = CloudApiVersion.V2,
                 _pipeline: bool = False,
                 _host: str = __url__,
                 _local: Locale = Locale.ZH_CN):
        super(Cloud, self).__init__(_apikey, _host)
        self.__apiver = _apiver
        self.__pipeline = _pipeline
        self.__locale = _local
        self.__limits = None

    def __make_path(self, *_path) -> str:
        path = [self.__PATH_PREFIX, self.__apiver]
        path.extend(_path)
        return "/".join(path)

    def __make_parm(self, _parm: tuple) -> dict:
        return {"query": [x for x in _parm], "locale": self.__locale}

    def __make_limits(self):
        if not self.__limits:
            path = self.__make_path(CloudApiPath.LIMITS)
            limits = self.query(path)
            self.__limits = AccountLimits(limits)

    def __into_pipeline(self, _path: str):
        if self.__pipeline:
            self.__make_limits()
            return self.__limits.pipeline(_path)
        return True

    def ip_as(self, *_data: str) -> list:
        path = CloudApiPath.IP_AS
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(_data))

    def ip_geo(self, *_data: str) -> list:
        path = CloudApiPath.IP_GEO
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(_data))

    def ip_whois(self, *_data: str) -> list:
        path = CloudApiPath.IP_WHOIS
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(_data))

    def domain_whois(self, *_data: str) -> list:
        path = CloudApiPath.DOMAIN_WHOIS
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(_data))

    def domain_rank(self, *_data: str) -> list:
        path = CloudApiPath.DOMAIN_RANK
        self.__into_pipeline(path)
        return self.query(self.__make_path(path), self.__make_parm(_data))
