## 分析过程
当前集客网关X86版本：V3.1 Build2020121800  
下载地址：http://file.cnrouter.com/index.php/Index/apbeta.html  

如何在浏览器里抓包，还请自行百度，抓包后可以看到，访问了2次/api/login的地址，第一次是get方式来获取json中的msg值，第二次是post方式用来提交登录的账号跟密码，经过多次抓包发现，loginid为登录账号，passwd为32位的md5登录密码，登录是经过js加密过的，每次登录都不一样。用loginid和passwd做为关键词搜索JS文件(/dest/jquery.all.js跟/dest/jkgw86.js)，在/dest/jquery.all.js中可以看到passwd是通过encryptPasswd函数来加密的，另外在/dest/jkgw86.js中可以看到在登录提交前把passwd用hex_md5(hex_md5(e.password) + a.msg)函数再次加密的，其中a.msg就是访问/api/login地址第一次是get方式来获取json中的msg值，知道了密码加密算法后，接下来就简单了，因为抓包返回的都是json。
在写py代码的时候，本来是用execjs来解密JS加密算法，py文件上传到HA里后，发现docker里的HA中没有JavaScript环境，后来换成js2py，就不用再配置JS环境了。

## 插件
github地址： https://github.com/xz0609/JiKe_GateWay_AC_HA

## HA的yaml配置
```python
device_tracker:
  - platform: jike_gateway_ac
    host: !secret jike_gateway_ac_host            # 必填项，集客网关AC的IP地址
    username: !secret jike_gateway_ac_username    # 必填项，集客网关AC的登录账号
    password: !secret jike_gateway_ac_password    # 必填项，集客网关AC的登录密码
    include:
      - K2P                                       # 可选项，值为AP的设备名称，用于过滤AP
      - RM2100

    # latitude: !secret home_latitude
    # longitude: !secret home_longitude

    consider_home: 30                             #设备离线延时
    interval_seconds: 15                          #扫描间隔时间
    new_device_defaults:
      track_new_devices: true
```
## 插件使用说明
把jike_gateway_ac文件夹放到HA的config/custom_components目录下，并按以上的yaml配置后，重启HA就可以了。

## 备注
网关AC默认是一分钟同步一次，所以扫描间隔时间不要设置太低了，没啥用，浪费资源。
按以上配置测试过，基本上90秒左右，HA里有反馈

![截图](https://raw.githubusercontent.com/xz0609/JiKe_GateWay_AC_HA/main/%E6%88%AA%E5%9B%BE-4085187.jpg)
