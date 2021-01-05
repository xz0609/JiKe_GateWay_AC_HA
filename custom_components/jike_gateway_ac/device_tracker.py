"""
Support for OpenWRT (luci) routers.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.luci/
"""
import json
import logging
import re
from os import path
import requests
import voluptuous as vol
import yaml
# import execjs
import js2py

import homeassistant.helpers.config_validation as cv
from homeassistant.exceptions import HomeAssistantError
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME,CONF_INCLUDE,CONF_LATITUDE,CONF_LONGITUDE

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_USERNAME): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Optional(CONF_INCLUDE, default=[]): vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_LATITUDE): vol.Coerce(float),
    vol.Optional(CONF_LONGITUDE): vol.Coerce(float),
})


class InvalidLuciTokenError(HomeAssistantError):
    """When an invalid token is detected."""

    pass


def get_scanner(hass, config):
    """Validate the configuration and return a Luci scanner."""
    scanner = Jike_Ac_GatewayDeviceScanner(config[DOMAIN])
    return scanner #if scanner.success_init else None


class Jike_Ac_GatewayDeviceScanner(DeviceScanner):
    """This class queries a wireless router running OpenWrt firmware."""

    def __init__(self, config):   #初始化函数，获取ip地址，用户名，密码
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self._include = config[CONF_INCLUDE]
        if 'latitude' in config.keys() and 'longitude' in config.keys():
            self.latitude = config[CONF_LATITUDE]
            self.longitude = config[CONF_LONGITUDE]
            self.x_y_flag=1
        else:self.x_y_flag=0
        print(self.host,self.username,self.password)

        self.last_results = {}   #定义一个字典。
        self.refresh_token()   #

        self.mac2name = None
        self.success_init = self.token is not None

    def refresh_token(self):  #刷新获取token后的函数
        """Get a new token."""
        self.token = _get_token(self.host, self.username, self.password)
        print(self.token)

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return self.last_results

    def get_extra_attributes(self, device):
        try:
            if self.result:
                if device in self.result:
                    if self.x_y_flag:
                        return {'rss':self.result[device]['rss'],
                        'AP':self.result[device]['ap'],
                        'ssid':self.result[device]['ssid'],
                        'latitude':self.latitude,
                        'longitude':self.longitude}
                    else:
                        return {'rss':self.result[device]['rss'],
                        'ssid':self.result[device]['ssid'],
                        'AP':self.result[device]['ap']}
                else :return {}
            else:
                _LOGGER.error('out')
                return {}
        except Exception as e:
            _LOGGER.error(e)
        else:return {}


    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        #if self.mac2name is None:
        if self.result:
            if device in self.result.keys():
                return self.result[device]['hostname']
            else:return False
        else:
            return False
        

    def _update_info(self):
        """Ensure the information from the Luci router is up to date.

        Returns boolean if scanning successful.
        """
        self.last_results=[]
        if not self.success_init:
            return False

        _LOGGER.info("集客网关AC 开始获取无线客户端数据")


        url='http://{}/api/apmgr'.format(self.host)
        header = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4195.1 Safari/537.36'
            }
        if self._include:
            search_key=str('|'.join(self._include))
        else:
            search_key=""
        data = {
            "action": "stasearch",
            "pagenum": 1,
            "numperpage": 1000,
            "searchkey": search_key,
            "sortkey": "tx_rate",
            "reverse": "yes"
            }

        try:
            r_json = self.token.post(url, data=data, headers=header).json()
            _LOGGER.debug('apmgr_ret_json'+str(r_json))
            if "search" not in r_json["msg"]:
                self.refresh_token()
                _LOGGER.error("_update_info，cooking过期，需要重新登陆")
                return 
            else:
                self.result=findallinfo(r_json)
        except InvalidLuciTokenError:
            _LOGGER.info("Refreshing token")
            self.refresh_token()
            return 

        if self.result:
            self.last_results = [i for i in self.result]
            #self.last_results = []
            #for device_entry in self.result:
            #    _LOGGER.error(device_entry)
            #    self.last_results.append(device_entry)
            return True
        else:
            return 


def _get_token(host, username, password):   #登陆web管理页面
    """Get authentication token for the given host+username+password."""
    url = 'http://{}/api/login'.format(host)
    return _req_json_rpc(url, 'login', username, password)

def _req_json_rpc(url, method, *args, **kwargs):   #处理登陆过程的函数
    """Perform one JSON RPC operation."""
    s = requests.Session()
    header = {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4195.1 Safari/537.36'
        }
    ret_msg_json = s.get(url, headers=header).json()
    _LOGGER.debug('login_token:'+ret_msg_json["msg"])
    encrypt_password = _encryptpasswd(args[1], ret_msg_json["msg"])
    data = {
        "loginid": args[0],
        "passwd": encrypt_password
        }
    _LOGGER.debug(data)
    try:
        res = s.post(url, data=data, headers=header)
    except requests.exceptions.Timeout:
        _LOGGER.exception("Connection to the router timed out")
        return

    if res.status_code == 200:   #如果状态码是200登陆成功，返回request.Session
        res_json = res.json()
        _LOGGER.debug(res_json)
        if '\u6210\u529f' not in res_json["msg"]:  # 登陆成功!
            _LOGGER.exception("Failed to authenticate, check your username and password")
            return 
        else:return s
    elif res.status_code == 401:  #如果返回状态码是401,提是登陆失败。
        # Authentication error
        _LOGGER.exception(
            "Failed to authenticate, check your username and password")
        return
    elif res.status_code == 403:  #服务器错误
        _LOGGER.exception("Luci responded with a 403 Invalid token")
        raise InvalidLuciTokenError

    else:  #其他错误
        _LOGGER.exception('Invalid response from luci: %s', res)
        return

def _encryptpasswd(password, msg):
    context = js2py.EvalJs()
    js_code = '''
        var hexcase = 0,
            b64pad = "",
            chrsz = 8;
        function hex_md5(a) {
            return binl2hex(core_md5(str2binl(a), a.length * chrsz))
        }

        function core_md5(a, b) {
            a[b >> 5] |= 128 << b % 32, a[(b + 64 >>> 9 << 4) + 14] = b;
            for (var c = 1732584193, d = -271733879, e = -1732584194, f = 271733878, g = 0; g < a.length; g += 16) {
                var h = c,
                    i = d,
                    j = e,
                    k = f;
                c = md5_ff(c, d, e, f, a[g + 0], 7, -680876936), f = md5_ff(f, c, d, e, a[g + 1], 12, -389564586), e = md5_ff(e,
                        f, c, d, a[g + 2], 17, 606105819), d = md5_ff(d, e, f, c, a[g + 3], 22, -1044525330), c = md5_ff(c, d,
                        e, f, a[g + 4], 7, -176418897), f = md5_ff(f, c, d, e, a[g + 5], 12, 1200080426), e = md5_ff(e, f, c, d,
                        a[g + 6], 17, -1473231341), d = md5_ff(d, e, f, c, a[g + 7], 22, -45705983), c = md5_ff(c, d, e, f, a[g +
                        8], 7, 1770035416), f = md5_ff(f, c, d, e, a[g + 9], 12, -1958414417), e = md5_ff(e, f, c, d, a[g + 10],
                        17, -42063), d = md5_ff(d, e, f, c, a[g + 11], 22, -1990404162), c = md5_ff(c, d, e, f, a[g + 12], 7,
                        1804603682), f = md5_ff(f, c, d, e, a[g + 13], 12, -40341101), e = md5_ff(e, f, c, d, a[g + 14], 17, -
                        1502002290), d = md5_ff(d, e, f, c, a[g + 15], 22, 1236535329), c = md5_gg(c, d, e, f, a[g + 1], 5, -
                        165796510), f = md5_gg(f, c, d, e, a[g + 6], 9, -1069501632), e = md5_gg(e, f, c, d, a[g + 11], 14,
                        643717713), d = md5_gg(d, e, f, c, a[g + 0], 20, -373897302), c = md5_gg(c, d, e, f, a[g + 5], 5, -
                        701558691), f = md5_gg(f, c, d, e, a[g + 10], 9, 38016083), e = md5_gg(e, f, c, d, a[g + 15], 14, -
                        660478335), d = md5_gg(d, e, f, c, a[g + 4], 20, -405537848), c = md5_gg(c, d, e, f, a[g + 9], 5,
                        568446438), f = md5_gg(f, c, d, e, a[g + 14], 9, -1019803690), e = md5_gg(e, f, c, d, a[g + 3], 14, -
                        187363961), d = md5_gg(d, e, f, c, a[g + 8], 20, 1163531501), c = md5_gg(c, d, e, f, a[g + 13], 5, -
                        1444681467), f = md5_gg(f, c, d, e, a[g + 2], 9, -51403784), e = md5_gg(e, f, c, d, a[g + 7], 14,
                        1735328473), d = md5_gg(d, e, f, c, a[g + 12], 20, -1926607734), c = md5_hh(c, d, e, f, a[g + 5], 4, -
                        378558), f = md5_hh(f, c, d, e, a[g + 8], 11, -2022574463), e = md5_hh(e, f, c, d, a[g + 11], 16,
                        1839030562), d = md5_hh(d, e, f, c, a[g + 14], 23, -35309556), c = md5_hh(c, d, e, f, a[g + 1], 4, -
                        1530992060), f = md5_hh(f, c, d, e, a[g + 4], 11, 1272893353), e = md5_hh(e, f, c, d, a[g + 7], 16, -
                        155497632), d = md5_hh(d, e, f, c, a[g + 10], 23, -1094730640), c = md5_hh(c, d, e, f, a[g + 13], 4,
                        681279174), f = md5_hh(f, c, d, e, a[g + 0], 11, -358537222), e = md5_hh(e, f, c, d, a[g + 3], 16, -
                        722521979), d = md5_hh(d, e, f, c, a[g + 6], 23, 76029189), c = md5_hh(c, d, e, f, a[g + 9], 4, -
                        640364487), f = md5_hh(f, c, d, e, a[g + 12], 11, -421815835), e = md5_hh(e, f, c, d, a[g + 15], 16,
                        530742520), d = md5_hh(d, e, f, c, a[g + 2], 23, -995338651), c = md5_ii(c, d, e, f, a[g + 0], 6, -
                        198630844), f = md5_ii(f, c, d, e, a[g + 7], 10, 1126891415), e = md5_ii(e, f, c, d, a[g + 14], 15, -
                        1416354905), d = md5_ii(d, e, f, c, a[g + 5], 21, -57434055), c = md5_ii(c, d, e, f, a[g + 12], 6,
                        1700485571), f = md5_ii(f, c, d, e, a[g + 3], 10, -1894986606), e = md5_ii(e, f, c, d, a[g + 10], 15, -
                        1051523), d = md5_ii(d, e, f, c, a[g + 1], 21, -2054922799), c = md5_ii(c, d, e, f, a[g + 8], 6,
                        1873313359), f = md5_ii(f, c, d, e, a[g + 15], 10, -30611744), e = md5_ii(e, f, c, d, a[g + 6], 15, -
                        1560198380), d = md5_ii(d, e, f, c, a[g + 13], 21, 1309151649), c = md5_ii(c, d, e, f, a[g + 4], 6, -
                        145523070), f = md5_ii(f, c, d, e, a[g + 11], 10, -1120210379), e = md5_ii(e, f, c, d, a[g + 2], 15,
                        718787259), d = md5_ii(d, e, f, c, a[g + 9], 21, -343485551), c = safe_add(c, h), d = safe_add(d, i), e =
                    safe_add(e, j), f = safe_add(f, k)
            }
            return Array(c, d, e, f)
        }

        function safe_add(a, b) {
            var c = (65535 & a) + (65535 & b),
                d = (a >> 16) + (b >> 16) + (c >> 16);
            return d << 16 | 65535 & c
        }

        function bit_rol(a, b) {
            return a << b | a >>> 32 - b
        }

        function md5_cmn(a, b, c, d, e, f) {
            return safe_add(bit_rol(safe_add(safe_add(b, a), safe_add(d, f)), e), c)
        }
        function md5_ff(a, b, c, d, e, f, g) {
            return md5_cmn(b & c | ~b & d, a, b, e, f, g)
        }
        function md5_gg(a, b, c, d, e, f, g) {
            return md5_cmn(b & d | c & ~d, a, b, e, f, g)
        }
        function md5_hh(a, b, c, d, e, f, g) {
            return md5_cmn(b ^ c ^ d, a, b, e, f, g)
        }
        function md5_ii(a, b, c, d, e, f, g) {
            return md5_cmn(c ^ (b | ~d), a, b, e, f, g)
        }

        function str2binl(a) {
            for (var b = Array(), c = (1 << chrsz) - 1, d = 0; d < a.length * chrsz; d += chrsz) b[d >> 5] |= (a.charCodeAt(d /
                chrsz) & c) << d % 32;
            return b
        }

        function binl2hex(a) {
            for (var b = hexcase ? "0123456789ABCDEF" : "0123456789abcdef", c = "", d = 0; d < 4 * a.length; d++) c += b.charAt(
                a[d >> 2] >> d % 4 * 8 + 4 & 15) + b.charAt(a[d >> 2] >> d % 4 * 8 & 15);
            return c
        }
        
        function hex_md5_s(p, m) {
            return hex_md5(hex_md5(p) + m)
        }
    '''
    context.execute(js_code)
    encrypt_passwd = context.hex_md5_s(password, msg)
    _LOGGER.debug(encrypt_passwd)
    return str(encrypt_passwd)

# def gethostname(dc):
    # if 'host_name' in dc.keys():
        # if dc['host_name']:return dc['host_name']
        # else:return dc['bssid'].upper().replace(':','')
    # else:return dc['bssid'].upper().replace(':','')

def findallinfo(ret_json):
    rest={}
    for i in ret_json['stalist']:
        # print('\n',i)
        mac_f = ':'.join(format(s, '02x') for s in bytes.fromhex(i['mac'].upper()))
        rest[mac_f]={"hostname": i["hostname"], "ip": i["ip"], "ap": i["name"], "ssid": i["ssid"], "rss": i["signal"]}
    return rest
