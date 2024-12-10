# analyze_log
Nginx日志安全分析脚本
### 功能

* 统计Top 20 地址
* SQL注入分析
* 扫描器告警分析
* 漏洞利用检测
* 敏感路径访问
* 文件包含攻击
* Webshell
* 寻找响应长度的url Top 20
* 寻找罕见的脚本文件访问
* 寻找302跳转的脚本文件
#参考
al0ne
#使用
./analyze_nginx_log.sh access.log
分析日志结果存于/tmp/logs
