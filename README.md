# IOC-Extractor

This IOC-Extractor script gets a list of ip addresses and finds the malicious ones using virustotal API.
in this version it only supports Virustotal, in future i will add support of more platforms and more other features.

## sampple 
ip_addresses = ["185.219.81.232","192.168.1.1","8.8.8.8"]
## output
```
[
    {
        "ip": "185.219.81.232",
        "type": "ip_address",
        "provider": [
            {
                "provider": "virustotal",
                "verdict": "malware"
            }
        ]
    },
    {
        "ip": "192.168.1.1",
        "type": "ip_address",
        "provider": [
            {
                "provider": "virustotal",
                "verdict": "clean"
            }
        ]
    },
    {
        "ip": "8.8.8.8",
        "type": "ip_address",
        "provider": [
            {
                "provider": "virustotal",
                "verdict": "malware"
            }
        ]
    }
]
```
