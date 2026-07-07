# The Picky Reality
## Remnawave

### Xray Confing (Profile)
<details><summary>Общий конфиг</summary>
  
```
  "inbounds": [
    {
      "tag": "Vless-TCP-Reality",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "xver": 0,
          "target": "127.0.0.1:1440", // to xHTTP
          "shortIds": [
            "shortId 1" // openssl rand -hex 16
          ],
          "privateKey": "key A",
          "serverNames": [
            "domain"
          ]
        }
      }
    },
    {
      "tag": "Vless-XHTTP-Reality",
      "port": 1440,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "xhttpSettings": {
          "mode": "auto",
          "path": "/api/v1/upload/"
        },
        "realitySettings": {
          "target": "127.0.0.1:1443", // to selfsteal
          "shortIds": [
            "shortId 1" // openssl rand -hex 16
          ],
          "privateKey": "key B",
          "serverNames": [
            "domain"
          ]
        }
      }
    },
    {
      "tag": "Hysteria2",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "hysteria",
      "settings": {
        "clients": [],
        "version": 2
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "finalmask": {
          "quicParams": {
            "type": "salamander",
            "debug": false,
            "settings": {
              "password": "password", // openssl rand -hex 16
              "packetSize": "512-1200"
            },
            "congestion": "bbr"
          }
        },
        "tlsSettings": {
          "alpn": [
            "h3"
          ],
          "serverName": "domain",
          "certificates": [
            {
              "keyFile": "/path/privkey.pem",
              "certificateFile": "/path/fullchain.pem"
            }
          ]
        },
        "hysteriaSettings": {
          "auth": "password", // openssl rand -hex 16
          "version": 2
        }
      }
    }
```

</details>

<details><summary>Vless-TCP-Reality</summary>
  
```
  "inbounds": [
    {
      "tag": "Vless-TCP-Reality",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "xver": 0,
          "target": "127.0.0.1:1443", // to xHTTP
          "shortIds": [
            "shortId 1" // openssl rand -hex 16
          ],
          "privateKey": "key A",
          "serverNames": [
            "domain"
          ]
        }
      }
    }
]
```

</details>

<details><summary>Vless-XHTTP-Reality</summary>
  
```
  "inbounds": [
    {
      "tag": "Vless-XHTTP-Reality",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls",
          "quic"
        ]
      },
      "streamSettings": {
        "network": "xhttp",
        "security": "reality",
        "xhttpSettings": {
          "mode": "auto",
          "path": "/api/v1/upload/"
        },
        "realitySettings": {
          "target": "127.0.0.1:1443", // to selfsteal
          "shortIds": [
            "shortId 1" // openssl rand -hex 16
          ],
          "privateKey": "key B",
          "serverNames": [
            "domain"
          ]
        }
      }
    }
]
```

</details>

<details><summary>Hysteria2</summary>
  
```
"inbounds": [
    {
      "tag": "Hysteria2",
      "port": 443,
      "listen": "0.0.0.0",
      "protocol": "hysteria",
      "settings": {
        "clients": [],
        "version": 2
      },
      "streamSettings": {
        "network": "hysteria",
        "security": "tls",
        "finalmask": {
          "quicParams": {
            "type": "salamander",
            "debug": false,
            "settings": {
              "password": "password", // openssl rand -hex 16
              "packetSize": "512-1200"
            },
            "congestion": "bbr"
          }
        },
        "tlsSettings": {
          "alpn": [
            "h3"
          ],
          "serverName": "domain",
          "certificates": [
            {
              "keyFile": "/path/privkey.pem",
              "certificateFile": "/path/fullchain.pem"
            }
          ]
        },
        "hysteriaSettings": {
          "auth": "password", // openssl rand -hex 16
          "version": 2
        }
      }
    }
]
```

</details>

## Mihomo rule-sets
### Directly services
> [!NOTE]
> Список сервисов которые следует пускать напрямую
<details><summary>Конфигурация шаблона</summary>
  
```
rule-providers:
  picky_directly_services:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/moocluck/mihomo-rules/raw/refs/heads/master/rule-sets/directly_services_domains.mrs
    path: ./rule-sets/picky_directly_services_domains.mrs
    interval: 86400
```
```
rules:
  - RULE-SET,picky_directly_services,DIRECT
```

</details>

### Proxied services
> [!NOTE]
> Список сервисов которые следует пускать через VPN
<details><summary>Конфигурация шаблона</summary>
  
```
rule-providers:
  picky_proxied_services:
    type: http
    behavior: domain
    format: mrs
    url: https://github.com/moocluck/mihomo-rules/raw/refs/heads/master/rule-sets/proxied_services_domains.mrs
    path: ./rule-sets/picky_proxied_services_domains.mrs
    interval: 86400
```
```
rules:
  - RULE-SET,picky_proxied_services,PROXY
```

</details>

### Другие rule-sets
- [Mihomo rule-sets](https://github.com/MetaCubeX/meta-rules-dat) by MetaCubeX include: asn/geoip/geosite
- [Mihomo rule-sets](https://github.com/legiz-ru/mihomo-rule-sets/tree/main) by Legiz-ru
