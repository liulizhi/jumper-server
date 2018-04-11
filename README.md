# rc-jumpser

## 1. Clone from Git
```
    git clone http://git.in.dataengine.com/devops/rc-jumpser.git /rc/local/rc-jumpser
```

## 2. Install dependency
```
    yum install -y  wget xz gcc automake zlib-devel openssl-devel.x86_64  python-devel.x86_64  python-pip.noarch
    wget https://www.python.org/ftp/python/3.6.1/Python-3.6.1.tar.xz && \
    tar xvf Python-3.6.1.tar.xz  && cd Python-3.6.1 && ./configure && make && make install &&  \
    rm -rf /tmp/{Python-3.6.1.tar.xz,Python-3.6.1}
    pip3 install --upgrade pip
    pip3 install -r requirements.txt -i http://pypi.douban.com/simple --trusted-host pypi.douban.com
```

## 3. Run
```
    /rc/local/rc-jumpser/ssh_test.py
```

## Changelog

### 2017-11-16
- l显示私钥，L显示公钥

### 2017-10-25
- 权限列表改为从元数据获取

### 2017-10-19
- 支持Python3

### 2017-10-16
- 回车键不再默认列出主机列表
- 配置文件增加IPA版本号
