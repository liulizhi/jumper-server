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

## 回放操作记录信息
scriptreplay sendal_sendal@192.168.1.136_113645.time sendal_sendal@192.168.1.136_113645.log
scriptreplay sendal_sendal@192.168.1.136_113645.time sendal_sendal@192.168.1.136_113645.txt
