# 守望者实验室威胁情报平台2.0客户端

**守望者实验室威胁情报平台2.0数据查询和下载官方Python客户端**

## 说明

* 本客户端旨在提供一种易于使用的威胁情报数据查询和下载方式

## 下载统计

[![Downloads](https://pepy.tech/badge/watcherlab-ti-client-python)](https://pepy.tech/project/watcherlab-ti-client-python)

## 客户端安装

```bash
pip install watcherlab-ti-client-python
```

## 威胁情报查询

```python
# 引入情报查询和下载2.0客户端
from watcherlab import ti
from watcherlab.enum import Locale

# 威胁情报平台2.0包含三个子系统：情报云端系统、情报中心系统和情报采集系统，本客户端目前支持前两个系统的部分API
# 创建情报云端系统，情报云端系统提供基础数据查询
# 参数说明：
# _apikey: 必须，用于识别账号身份，和1.0版本的"Token"含义相同，为了防止混淆2.0版本中被重命名为"APIKEY"，在登陆系统后的[用户中心]中获取
# _apiver: 可选，要使用的API版本，在威胁情报平台2.0中API的初始版本为V2，当前亦只有V2，默认为V2
# _host: 可选，要连接的主机地址，当存在私有化部署版本时需要修改为私有化系统的主机地址，默认为ti.__url__
# _pipeline: 可选，是否由本客户端管道化查询，服务端对查询频率进行了限制因此一旦查询频率超过限制将引发ti.PlatformResponseError异常
#            该选项设置为True时客户端将在检测到查询频率达到限制是休眠当前调用者线程并在最短的时间后自动提交查询，代价是将导致调用者线
#            程休眠一段时间，这可能引发其他的副作用请谨慎使用，值得注意的是由于网络等不可控原因即使开启了此选项依然有小概率引发
#            ti.PlatformResponseError异常，默认为False
# _local: 可选，未充分实现，最稳妥的方式是不要传递次参数
cloud = ti.Cloud(_apikey="APIKEY",
                 _apiver=ti.CloudApiVersion.V2,
                 _host="https://ti.watcherlab.com",
                 _pipeline=False,
                 _local=Locale.ZH_CN)

# 创建情报中心系统，情报中心系统提供威胁情报查询和订阅数据下载
# 参数说明：参考ti.Cloud()的参数说明，有所不同的是API的版本需要设置为情报中心系统的API版本即使当前它们的实际值相同
core = ti.Core(_apikey="APIKEY",
               _apiver=ti.CoreApiVersion.V2,
               _host="https://ti.watcherlab.com",
               _pipeline=False,
               _local=Locale.ZH_CN)

# 创建威胁情报查询器，提供威胁情报查询，我们还为不同的数据类型单独提供了不同的专属类因此无需情报类型参数
# 参数说明：
# _core: 要使用的情报中心系统类
# _type: 要查询的情报数据类型
querier = ti.Querier(_core=core, _type=ti.IntelligenceType.IP)
ip_querier = ti.IpQuerier(_core=core)
domain_querier = ti.DomainQuerier(_core=core)
url_querier = ti.UrlQuerier(_core=core)
email_querier = ti.EmailQuerier(_core=core)
md5_querier = ti.MD5Querier(_core=core)
sha1_querier = ti.SHA1Querier(_core=core)
sha256_querier = ti.SHA256Querier(_core=core)
sha512_querier = ti.SHA512Querier(_core=core)
sm3_querier = ti.SM3Querier(_core=core)

# 查询厂商威胁情报数据，厂商威胁情报数据是权威的政府机构、开源组织或者私营公司的数据
# 参数说明：
# *_data: 要查询的威胁情报数据，动态参数可以同时查询多个数据，数据的实际类型必须同查询器_type参数合适
# 返回值说明：返回的数据类型为dict[str, Intelligence{XXX}]，使用不同的数据类型将返回不同的Intelligence{XXX}类型，例如IntelligenceIp
result = querier.vendor("IP_ADDRESS")

# 查询其它来源的威胁情报数据
# 查询公开的威胁情报数据
public_result = querier.public("IP_ADDRESS")
# 查询自定义或者手动上传的威胁情报数据
custom_result = querier.custom("IP_ADDRESS")
# 查询由第三方终端设备推送的检测日志而生成的威胁情报数据
device_result = querier.device("IP_ADDRESS")

# 查询威胁情报的基础数据，不同的数据类型有不同的基础数据获取方法，例如获取IP地址类型的威胁情报数据的地理位置信息
# 参数说明：
# _cloud: 情报云端系统，基础数据均来自情报云端系统
# 返回值说明：返回的数据类型为ti.GeoIp
result["IP_ADDRESS"].geo(_cloud=cloud)

# IP地址类型我们目前提供了如下的基础数据查询方法
# geo(): IP地理位置，返回值为ti.GeoIp类型
# whois(): IP Whois，返回值为str类型
# autonomous_system(): IP自治域信息，返回值为list[ti.AutonomousSystem]类型
```

## 威胁情报订阅数据下载

```python
# 引入情报查询和下载2.0客户端
from watcherlab import ti
from watcherlab.enum import Locale

# 威胁情报平台2.0包含三个子系统：情报云端系统、情报中心系统和情报采集系统，本客户端目前支持前两个系统的部分API
# 创建情报云端系统，情报云端系统提供基础数据查询
# 参数说明：
# _apikey: 必须，用于识别账号身份，和1.0版本的"Token"含义相同，为了防止混淆2.0版本中被重命名为"APIKEY"，在登陆系统后的[用户中心]中获取
# _apiver: 可选，要使用的API版本，在威胁情报平台2.0中API的初始版本为V2，当前亦只有V2，默认为V2
# _host: 可选，要连接的主机地址，当存在私有化部署版本时需要修改为私有化系统的主机地址，默认为ti.__url__
# _pipeline: 可选，是否由本客户端管道化查询，服务端对查询频率进行了限制因此一旦查询频率超过限制将引发ti.PlatformResponseError异常
#            该选项设置为True时客户端将在检测到查询频率达到限制是休眠当前调用者线程并在最短的时间后自动提交查询，代价是将导致调用者线
#            程休眠一段时间，这可能引发其他的副作用请谨慎使用，值得注意的是由于网络等不可控原因即使开启了此选项依然有小概率引发
#            ti.PlatformResponseError异常，默认为False
# _local: 可选，未充分实现，最稳妥的方式是不要传递次参数
cloud = ti.Cloud(_apikey="APIKEY",
                 _apiver=ti.CloudApiVersion.V2,
                 _host="https://ti.watcherlab.com",
                 _pipeline=False,
                 _local=Locale.ZH_CN)

# 创建情报中心系统，情报中心系统提供威胁情报查询和订阅数据下载
# 参数说明：参考ti.Cloud()的参数说明，有所不同的是API的版本需要设置为情报中心系统的API版本即使当前它们的实际值相同
core = ti.Core(_apikey="APIKEY",
               _apiver=ti.CoreApiVersion.V2,
               _host="https://ti.watcherlab.com",
               _pipeline=False,
               _local=Locale.ZH_CN)

# 创建威胁情报订阅，可以用来查询当前可下载的威胁情报数据并下载
# 参数说明：
# _core: 要使用的情报中心系统类
feed = ti.Feed(_core=core)

# 获取当前可下载的威胁情报数据列表
# 返回值说明：返回的数据类型为ti.FeedList
feed_list = feed.list()

# 下载威胁情报数据
# 参数说明：
# *_tags: 动态参数，要下载的威胁情报数据的标签类型，可以从feed.list()方法中获取可下在的所有类型
# _limits: 可选，建议服务端返回的威胁情报数量，建议不一定采纳但尽量被满足，实际返回的数量由服务端根据当前可用的数据量、负载等情况
#          决定实际返回的数量，默认为100
# _confidence: 可选，返回的情报可信度必须满足此要求，要求一定被采纳。可用的范围为0=100，默认为50
# _decision: 可选，返回的情报决策，要求一定被采纳。默认不设置此要求
# _inevent: 可选，返回的情报是否存在于服务端的事件报告中，要求一定被采纳。默认不设置此要求
# _type: 可选，返回的情报数据类型，要求一定被采纳。默认不设置此要求
# 返回值说明：返回的数据类型为dict[str, ti.FeedItem]
feed_data = feed.download(104002, 104002,
                          _limits=100,
                          _confidence=50,
                          _decision=ti.Decision.BLOCK,
                          _inevent=True,
                          _type=ti.IntelligenceType.IP)
```