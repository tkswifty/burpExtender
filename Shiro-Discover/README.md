# Shiro-Discover

## 介绍

尝试提供自动发现使用了shiro依赖的Web站点的Burp插件

## 使用

相关shiro版本默认使用了CookieRememberMeManager,由于AES使用默认的KEY/常见的KEY/KEY泄露,导致反序列化的cookie可控，从而引发反序列化攻击。

在日常测试或者红蓝对抗中，相比手工在cookie写入rememberMe字段进行判断，若是能直接在BurpSuite抓包中，在请求时自动化完成这个检测，会方便很多。因此，这里提供一个BurpSuite插件，可快速对访问过的站点检测是否使用了shiro依赖，快速筛选出对应的站点进一步进行安全检查。导入BurpSuite中即可进行使用。

使用演示：

若是相关站点使用了shiro依赖，会在history里橙色高亮显示：

![image](https://github.com/tkswifty/Burp_Extender/blob/master/Shiro-Discover/shiro.png)


## TODO

在后续尝试联合OOB进行漏洞检测。

