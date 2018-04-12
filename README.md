# jumpser-server

## 1. 使用方法：
    安装python3的环境
    安装相应的pip包
    修改默认的shell为当前脚本
    配置配置文件
    远程登录的时候，就是跳板机了


## 回放操作记录信息
```
    scriptreplay sendal_sendal@192.168.1.136_113645.time sendal_sendal@192.168.1.136_113645.log
    scriptreplay sendal_sendal@192.168.1.136_113645.time sendal_sendal@192.168.1.136_113645.txt
```

## Todo
1. 记录程序日志
2. 加入metrics监控，可以查看当前在线人数，机器性能等
3. 支持资源信息通过api获取，或者db获取等
4. 支持win rdp跳板机支持
5. 更多...
