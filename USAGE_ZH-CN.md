# 使用说明

## 安装客户端

```bash
pip install watcherlab-ti-client-python
```

## 威胁情报查询

```python
# 引入适用于威胁情报2.0版本的Python客户端
from watcherlab import ti
from watcherlab.enum import Locale

# 创建情报云端子系统，情报云端子系统提供基础数据查询，例如Whois数据，IpGeo数据等
# 参数说明：
# _apikey: 必须，用于识别账号身份。和1.0版本的"Token"含义相同，为了防止混淆2.0版本中被重命名为"APIKEY"，在登陆系统后的[用户中心]中获取
# _apiver: 可选，要使用的API版本。在威胁情报平台2.0中API的初始版本为V2，当前亦只有V2，默认为V2
# _host: 可选，要连接的主机地址。当存在私有化部署版本时需要修改为私有化系统的主机地址，默认为ti.__url__
# _pipeline: 可选，是否由本客户端管道化查询。为了防止服务被滥用，服务端对查询频率进行了限制因此一旦查询频率超过限制将引发ti.PlatformResponseError异常，该选项设置为True时客户端将在检测到查询频率达到限制时休眠当前调用者线程一段时间，休眠结束后将自动提交查询，代价是将导致调用者线程休眠一段时间，这可能引发其他的副作用请谨慎使用。值得注意的是由于网络等不可控原因即使开启了此选项依然有小概率引发异常，默认为False
# _local: 可选，未充分实现。最稳妥的方式是保持默认选项
cloud = ti.Cloud(_apikey="APIKEY",
                 _apiver=ti.CloudApiVersion.V2,
                 _host="https://ti.watcherlab.com",
                 _pipeline=False,
                 _local=Locale.ZH_CN)

# 创建情报中心子系统，情报中心子系统提供威胁情报查询和订阅数据下载
# 参数说明：参考ti.Cloud()的参数说明，有所不同的是API的版本需要设置为情报中心系统的API版本即使当前它们的实际值相同
core = ti.Core(_apikey="APIKEY",
               _apiver=ti.CoreApiVersion.V2,
               _host="https://ti.watcherlab.com",
               _pipeline=False,
               _local=Locale.ZH_CN)

# 创建威胁情报查询器，提供威胁情报查询
# 参数说明：
# _core: 情报中心子系统
# _type: 情报数据类型
querier = ti.Querier(_core=core, _type=ti.IntelligenceType.IP)

# 我们还为不同的数据类型单独提供了不同的专属类因此无需情报类型参数
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
# *_data: 要查询的威胁情报数据。动态参数，可以同时查询多个数据，数据的实际类型必须同查询器_type参数合适
# 返回值类型：dict[str, Intelligence{XXX}]
# 使用不同的数据类型将返回不同的Intelligence{XXX}类型，例如IntelligenceIp
result = querier.vendor("IP_ADDRESS")

# 查询其它来源的威胁情报数据
# 查询公开的威胁情报数据
public_result = querier.public("IP_ADDRESS")
# 查询自定义或者手动上传的威胁情报数据
custom_result = querier.custom("IP_ADDRESS")
# 查询由第三方攻击检测设备推送的检测日志而生成的威胁情报数据
device_result = querier.device("IP_ADDRESS")

# 查询威胁情报的基础数据。不同的数据类型有不同的基础数据获取方法，例如获取IP地址类型的威胁情报数据的地理位置信息
# 参数说明：
# _cloud: 情报云端子系统
# 返回值类型：ti.GeoIp
result["IP_ADDRESS"].geo(_cloud=cloud)

# IP地址类型我们目前提供了如下的基础数据查询方法
# geo(): IP地理位置
# whois(): IP Whois
# autonomous_system(): IP自治域信息
```

## 威胁情报订阅数据下载

```python
# 引入适用于威胁情报2.0版本的Python客户端
from watcherlab import ti
from watcherlab.enum import Locale

# 创建威胁情报中心子系统
core = ti.Core("APIKEY")

# 创建威胁情报订阅。可以用来查询和下载威胁情报数据
# 参数说明：
# _core: 情报中心子系统
feed = ti.Feed(_core=core)

# 获取当前可下载的威胁情报数据列表
# 返回值类型：ti.FeedList
feed_list = feed.list()

# 下载威胁情报数据
# 参数说明：
# *_tags: 动态参数，可同时查询多个数据，要下载的威胁情报数据的威胁（标签）类型。可以从feed.list()方法中获取
# _limits: 可选，建议服务端返回的威胁情报的数量。实际返回的数量由服务端根据当前可用的数据、负载等情况决定实际返回的数量，默认为100
# _confidence: 可选，返回的情报可信度。可用的范围为[0-100]，默认为50，降低此要求可能会获得更接近于_limits参数指定的情报数量
# _decision: 可选，返回的情报决策。默认不设置此要求，降低此要求可能会获得更接近于_limits参数指定的情报数量
# _inevent: 可选，返回的情报是否存在于服务端的事件报告中，设置为True则数据均位于某个事件报告中，设置为False则数据均不位于事件报告中。默认不设置此要求因此返回的数据可能存在于某个事件报告中，不设置此要求可能会获得更接近于_limits参数指定的情报数量
# _type: 可选，返回的情报数据类型。默认不设置此要求，返回的数据类型将由服务端自行决定，不设置此要求可能会获得更接近于_limits参数指定的情报数量
# 返回值类型：dict[str, ti.FeedItem]
feed_data = feed.download(104002, 104002,
                          _limits=100,
                          _confidence=50,
                          _decision=ti.Decision.BLOCK,
                          _inevent=True,
                          _type=ti.IntelligenceType.IP)
```
