# IOC-Extractor
## update : [support of Abuse IPDB added]

This IOC-Extractor script gets a list of ip addresses and finds the malicious ones using security platform APIs.
in this version it  supports Virustotal,abuse IPDB.in future i will add support of more platforms and more other features.

## sample 
ip_addresses = ["185.219.81.232","43.156.118.145","195.158.24.42"]
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
            },
            {
                "provider": "abuse_ipdb",
                "verdict": "clean"
            }
        ]
    },
    {
        "ip": "43.156.118.145",
        "type": "ip_address",
        "provider": [
            {
                "provider": "virustotal",
                "verdict": "malicious"
            },
            {
                "provider": "abuse_ipdb",
                "verdict": "malicious"
            }
        ]
    },
    {
        "ip": "195.158.24.42",
        "type": "ip_address",
        "provider": [
            {
                "provider": "virustotal",
                "verdict": "malicious"
            },
            {
                "provider": "abuse_ipdb",
                "verdict": "malicious"
            }
        ]
    }
]
```
