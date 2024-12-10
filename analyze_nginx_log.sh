#!/usr/bin/env bash

echo ""
echo " ========================================================= "
echo " \                 Nginx日志安全分析脚本 V0.1           / "
echo " ========================================================= "
echo " # 支持Nginx日志分析，攻击告警分析等                    "
echo " # author：fireskyno1                    "
echo " # https://github.com/fireskyno1/analyze_log                   "
echo -e "\n"

# 分析结果存储目录，结尾不能加/
outfile=/tmp/logs
# 如果目录已存在则清空，未存在则新建目录
if [ -d $outfile ]; then
    rm -rf $outfile/*
else
    mkdir -p $outfile
fi

# 验证操作系统是 debian 系还是 CentOS
OS='None'
if [ -e "/etc/os-release" ]; then
    source /etc/os-release
    case ${ID} in
    "debian" | "ubuntu" | "devuan")
        OS='Debian'
        ;;
    "centos" | "rhel fedora" | "rhel")
        OS='Centos'
        ;;
    *) ;;
    esac
fi

if [ $OS = 'None' ]; then
    if command -v apt-get >/dev/null 2>&1; then
        OS='Debian'
    elif command -v yum >/dev/null 2>&1; then
        OS='Centos'
    else
        echo -e "\n不支持这个系统\n"
        echo -e "已退出"
        exit 1
    fi
fi

# 检测 ag 软件有没有安装
if ag -V >/dev/null 2>&1; then
    echo -e "\e[00;32msilversearcher-ag 已安装 \e[00m"
else
    if [ $OS = 'Centos' ]; then
        yum -y install the_silver_searcher >/dev/null 2>&1
    else
        apt-get -y install silversearcher-ag >/dev/null 2>&1
    fi
fi

function analyze_top_ips() {
    echo -e "\e[00;31m[+]TOP 20 IP 地址\e[00m"
    ag -a -o --nofilename '((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}' /var/log/nginx/*.log | sort | uniq -c | sort -nr | head -n 20 | tee -a $outfile/top20.log
}

function analyze_sql_injection() {
    echo -e "\e[00;31m[+]SQL注入攻击分析\e[00m"
    ag -a "xp_cmdshell|%20xor|%20and|%20AND|%20or|%20OR|select%20|%20and%201=1|%20and%201=2|%20from|%27exec|information_schema.tables|load_file|benchmark|substring|table_name|table_schema|%20where%20|%20union%20|%20UNION%20|concat\(|concat_ws\(|%20group%20|0x5f|0x7e|0x7c|0x27|%20limit|\bcurrent_user\b|%20LIMIT|version%28|version\(|database%28|database\(|user%28|user\(|%20extractvalue|%updatexml|rand\(0\)\*2|%20group%20by%20x|%20NULL%2C|sqlmap" /var/log/nginx/*.log | ag -v '/\w+\.(?:js|css|html|jpg|jpeg|png|htm|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >$outfile/sql.log
    awk '{print "SQL注入攻击" NR"次"}' $outfile/sql.log | tail -n1
    echo "SQL注入 TOP 20 IP 地址"
    ag -o '(?<=:)((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}' $outfile/sql.log | sort | uniq -c | sort -nr | head -n 20 | tee -a $outfile/sql_top20.log
    # 重点关注 from 查询，是否存在脱裤行为，排除扫描行为
    echo "SQL注入 FROM 查询"
    cat $outfile/sql.log | ag '\bfrom\b' | ag -v 'information_schema' >$outfile/sql_from_query.log
    awk '{print "SQL注入 FROM 查询" NR"次"}' $outfile/sql_from_query.log | tail -n1
}

function analyze_scanners() {
    echo -e "\e[00;31m[+]扫描器 scan & 黑客工具\e[00m"
    ag -a "acunetix|by_wvs|nikto|netsparker|HP404|nsfocus|WebCruiser|owasp|nmap|nessus|HEAD /|AppScan|burpsuite|w3af|ZAP|openVAS|.+avij|.+angolin|360webscan|webscan|XSS@HERE|XSS%40HERE|NOSEC.JSky|wwwscan|wscan|antSword|WebVulnScan|WebInspect|ltx71|masscan|python-requests|Python-urllib|WinHttpRequest" /var/log/nginx/*.log | ag -v '/\w+\.(?:js|css|jpg|jpeg|png|swf)(?:\?| )' | awk '($9==200)||($9==500) {print $0}' >$outfile/scan.log
    awk '{print "共检测到扫描攻击" NR"次"}' $outfile/scan.log | tail -n1
    echo "扫描工具流量 TOP 20"
    ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' $outfile/scan.log | sort | uniq -c | sort -nr | head -n 20 | tee -a $outfile/scan_top20.log
}

function analyze_sensitive_paths() {
    echo -e "\e[00;31m[+]敏感路径访问\e[00m"
    ag -a "/_cat/|/_config/|include=|phpinfo|info\.php|/web-console|JMXInvokerServlet|/manager/html|axis2-admin|axis2-web|phpMyAdmin|phpmyadmin|/admin-console|/jmx-console|/console/|\.tar.gz|\.tar|\.tar.xz|\.xz|\.zip|\.rar|\.mdb|\.inc|\.sql|/\.config\b|\.bak|/.svn/|/\.git/|\.hg|\.DS_Store|\.htaccess|nginx\.conf|\.bash_history|/CVS/|\.bak|wwwroot|备份|/Web.config|/web.config|/1.txt|/test.txt" /var/log/nginx/*.log | awk '($9==200)||($9==500) {print $0}' >$outfile/dir.log
    awk '{print "共检测到针对敏感文件扫描" NR"次"}' $outfile/dir.log | tail -n1
    echo "敏感文件访问流量 TOP 20"
    ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' $outfile/dir.log | sort | uniq -c | sort -nr | head -n 20 | tee -a $outfile/dir_top20.log
}

function analyze_vulnerability_exploits() {
    echo -e "\e[00;31m[+]漏洞利用检测\e[00m"
    ag -a "%00|/win.ini|/my.ini|\.\./\.\./|/etc/shadow|%0D%0A|file:/|gopher:/|dict:/|WindowsPowerShell|/wls-wsat/|call_user_func_array|uddiexplorer|@DEFAULT_MEMBER_ACCESS|@java\.lang\.Runtime|OgnlContext|/bin/bash|cmd\.exe|wget\s|curl\s|s=/index/\think" /var/log/nginx/*.log | awk '($9==200)||($9==500) {print $0}' >$outfile/exploit.log
    awk '{print "漏洞利用探测" NR"次"}' $outfile/exploit.log | tail -n1
    echo "漏洞利用检测 TOP 20"
    ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' $outfile/exploit.log | sort | uniq -c | sort -nr | head -n 20 | tee -a $outfile/exploit_top20.log
}

function analyze_webshells() {
    echo -e "\e[00;31m[+]webshell\e[00m"
    ag -a "=whoami|dbname=|exec=|cmd=|\br57\b|\bc99\b|\bc100\b|\bb374k\b|adminer.php|eval\(|assert\(|%eval|%execute|tunnel\.[asp|php|jsp|aspx]{3,4}|makewebtaski|ma\.[asp|php|jsp|aspx]{3,4}|\bup\.[asp|php|jsp|aspx]{3,4}|cmd\.[asp|php|jsp|aspx]{3,4}|201\d\.[asp|php|jsp|aspx]{3,4}|xiaoma\.[asp|php|jsp|aspx]{3,4}|shell\.[asp|php|jsp|aspx]{3,4}|404\.[asp|php|jsp|aspx]{3,4}|tom\.[asp|php|jsp|aspx]{3,4}|k8cmd\.[asp|php|jsp|aspx]{3,4}|ver[0-9]{3,4}\.[asp|php|jsp|aspx]{3,4}|\.aar|[asp|php|jsp|aspx]{3,4}spy\.|o=vLogin|aioshell|admine|ghost\.[asp|php|jsp|aspx]{3,4}|r00ts|90sec|t00ls|editor\.aspx|wso\.[asp|aspx]{3,4}" /var/log/nginx/*.log | awk '($9==200)||($9==500) {print $0}' >$outfile/webshell.log
    awk '{print "共检测到 webshell 行为" NR"次"}' $outfile/webshell.log | tail -n1
    echo "Webshell TOP 20"
    ag -o '(?<=:)\d+\.\d+\.\d+\.\d+' $outfile/webshell.log | sort | uniq -c | sort -nr | head -n 20 | tee -a $outfile/webshell_top20.log
}

function analyze_http_tunnels() {
    echo -e "\e[00;31m[+]HTTP Tunnel\e[00m"
    # Regeorg 代理特征
    ag -a "cmd=disconnect|cmd=read|cmd=forward|cmd=connect|127.0.0.1" /var/log/nginx/*.log | awk '($9==200)||($9==500) {print $0}' | tee -a $outfile/tunnel.log
    awk '{print "共检测到隧道行为" NR"次"}' $outfile/tunnel.log | tail -n1
}

function analyze_top_url_response_lengths() {
    echo -e "\e[00;31m[+]Top 20 url 响应长度\e[00m"
    # 查找 url 响应长度最长的 url 排序，目的是有没有下载服务器的一些打包文件
    len=$(cat /var/log/nginx/*.log | awk '{print $10}' | sort -nr | head -n 20)
    echo $len | awk 'BEGIN{ RS=" " }{ print $0 }' | xargs -i{} ag -a --nocolor '\d+\s{}\s' /var/log/nginx/*.log | awk '{print $7,$10}' | sort | uniq | sort -k 2 -nr | tee -a $outfile/url_rsp_len.log
}

function analyze_rare_script_accesses() {
    echo -e "\e[00;31m[+]罕见的脚本文件访问\e[00m"
    echo "访问量特别特别少的脚本文件极有可能是 webshell"
    cat /var/log/nginx/*.log | awk '($9==200)||($9==500) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a $outfile/rare_url.log
}

function analyze_302_redirects() {
    echo -e "\e[00;31m[+]302 跳转\e[00m"
    echo "此目的是寻找一些登录成功的脚本文件"
    cat /var/log/nginx/*.log | awk '($9==302)||($9==301) {print $7}' | sort | uniq -c | sort -n | ag -v '\?' | ag '\.php|\.jsp|\.asp|\.aspx' | head -n 20 | tee -a $outfile/302_goto.log
}

echo "分析结果日志：${outfile}"
echo -e "\n"

analyze_top_ips
analyze_sql_injection
analyze_scanners
analyze_sensitive_paths
analyze_vulnerability_exploits
analyze_webshells
analyze_http_tunnels
analyze_top_url_response_lengths
analyze_rare_script_accesses
analyze_302_redirects
