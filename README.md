
# wifigod

**[改动自apfree_wifidog](https://github.com/liudf0716/apfree_wifidog)**

## 功能说明

* 用json格式做配置文档．json数据文件格式，单行第一个字符"#"，为注释，读取时将去除．原config_init不变，初始化后，在读取wifidog.json文件，重新赋值.

* gs开头的文件为添加的功能，利用ping的心跳，与服务器通信，根据返回的数据进行相应的设置请求．

* wifidog启动时，先注册

* 含读取串口(改编至comgt源码,添加pdu中文编码)，发送AT指令，即可以发送中文短信．电信联通发送短信格式不一样，需要区别对待


