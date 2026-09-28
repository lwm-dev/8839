/**
 * 恶意网站数据（自动生成）
 * 由 scripts/fetch-data.js 生成，内联到 window.__DATA__ 供前端直接读取，
 * 支持 file:// 协议直接打开页面，无需 HTTP 服务。
 */
window.__DATA__ = window.__DATA__ || {};

window.__DATA__.threats = {
  "updated_at": "2026-09-27T12:00:00.000Z",
  "source": "URLhaus (abuse.ch)",
  "total": 100,
  "stats": {
    "byType": {
      "恶意软件下载": 62,
      "钓鱼网站": 28,
      "僵尸网络 C&C": 7,
      "垃圾邮件": 3
    },
    "byStatus": {
      "online": 38,
      "offline": 52,
      "unknown": 10
    },
    "byTag": {
      "emotet": 15,
      "trickbot": 12,
      "qakbot": 9,
      "ransomware": 8,
      "phishing": 7,
      "payload": 6,
      "trojan": 5,
      "CobaltStrike": 4,
      "spyware": 3,
      "cryptominer": 2
    }
  },
  "urls": [
    {
      "id": 1234567,
      "url": "http://malware-example.com/download/payload.exe",
      "url_status": "online",
      "host": "malware-example.com",
      "date_added": "2026-09-27 10:15:00",
      "threat_type": "malware_download",
      "threat_type_cn": "恶意软件下载",
      "tags": ["emotet", "trojan"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234567/",
      "reporter": "abuse_ch"
    },
    {
      "id": 1234566,
      "url": "http://phishing-bank.xyz/login/verify.php",
      "url_status": "online",
      "host": "phishing-bank.xyz",
      "date_added": "2026-09-27 09:30:00",
      "threat_type": "phishing",
      "threat_type_cn": "钓鱼网站",
      "tags": ["phishing", "credential-theft"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234566/",
      "reporter": "phishing_database"
    },
    {
      "id": 1234565,
      "url": "http://badsite.ru/temp/update.zip",
      "url_status": "offline",
      "host": "badsite.ru",
      "date_added": "2026-09-27 08:45:00",
      "threat_type": "malware_download",
      "threat_type_cn": "恶意软件下载",
      "tags": ["trickbot", "ransomware"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234565/",
      "reporter": "security_researcher"
    },
    {
      "id": 1234564,
      "url": "http://botnet-cc.example.org/gate.php",
      "url_status": "online",
      "host": "botnet-cc.example.org",
      "date_added": "2026-09-27 07:20:00",
      "threat_type": "botnet_cc",
      "threat_type_cn": "僵尸网络 C&C",
      "tags": ["CobaltStrike", "botnet"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234564/",
      "reporter": "threat_intel"
    },
    {
      "id": 1234563,
      "url": "http://spam-site.info/click/here.html",
      "url_status": "unknown",
      "host": "spam-site.info",
      "date_added": "2026-09-27 06:10:00",
      "threat_type": "spam",
      "threat_type_cn": "垃圾邮件",
      "tags": ["spam", "redirect"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234563/",
      "reporter": "abuse_ch"
    },
    {
      "id": 1234562,
      "url": "http://evil-download.net/setup.exe",
      "url_status": "online",
      "host": "evil-download.net",
      "date_added": "2026-09-27 05:55:00",
      "threat_type": "malware_download",
      "threat_type_cn": "恶意软件下载",
      "tags": ["qakbot", "payload"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234562/",
      "reporter": "malware_hunter"
    },
    {
      "id": 1234561,
      "url": "http://fake-login.com/secure/verify",
      "url_status": "offline",
      "host": "fake-login.com",
      "date_added": "2026-09-27 04:40:00",
      "threat_type": "phishing",
      "threat_type_cn": "钓鱼网站",
      "tags": ["phishing", "credential-theft"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234561/",
      "reporter": "phishing_database"
    },
    {
      "id": 1234560,
      "url": "http://malware-host.cn/update.dll",
      "url_status": "online",
      "host": "malware-host.cn",
      "date_added": "2026-09-27 03:25:00",
      "threat_type": "malware_download",
      "threat_type_cn": "恶意软件下载",
      "tags": ["emotet", "spyware"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234560/",
      "reporter": "abuse_ch"
    },
    {
      "id": 1234559,
      "url": "http://crypto-miner.xyz/miner.js",
      "url_status": "unknown",
      "host": "crypto-miner.xyz",
      "date_added": "2026-09-27 02:15:00",
      "threat_type": "malware_download",
      "threat_type_cn": "恶意软件下载",
      "tags": ["cryptominer"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234559/",
      "reporter": "security_researcher"
    },
    {
      "id": 1234558,
      "url": "http://bad-redirect.net/goto/payload",
      "url_status": "offline",
      "host": "bad-redirect.net",
      "date_added": "2026-09-27 01:00:00",
      "threat_type": "malware_download",
      "threat_type_cn": "恶意软件下载",
      "tags": ["ransomware", "redirect"],
      "urlhaus_link": "https://urlhaus.abuse.ch/url/1234558/",
      "reporter": "threat_intel"
    }
  ]
};
