"""
异常类
"""


class PlatformError(Exception):
    def __init__(self, *args, **kwargs):
        pass


class PlatformResponseError(PlatformError):
    def __init__(self, _data: dict):
        self.code = _data["code"]
        self.msg = _data["msg"]

    def __str__(self):
        return "Response code: {0.code}, message: {0.msg}".format(self)


class SerializeError(Exception):
    def __init__(self, *args, **kwargs):
        pass

    def __str__(self):
        return "Serialize data may be incorrect"


class SerializeTypeError(Exception):
    def __init__(self, _data: dict, _need):
        self.data = _data["query"]
        self.type = _data["type"]
        self.need = _need

    def __str__(self):
        return "Serialize data type error, need: {0.need}, but give: {0.type}".format(self)


class DeserializeError(Exception):
    def __init__(self, *args, **kwargs):
        pass
