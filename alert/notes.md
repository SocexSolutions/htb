# Alert

[alert](https://app.hackthebox.com/machines/Alert)

IP: 10.10.11.44

# Scanning

## Nmap

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-24 17:47 MST
Nmap scan report for 10.10.11.44
Host is up (0.060s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://alert.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=11/24%OT=22%CT=1%CU=38632%PV=Y%DS=3%DC=T%G=Y%TM=674
OS:3C938%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%II=I%TS=A)SEQ(
OS:SP=105%GCD=1%ISR=109%TI=Z%CI=Z)SEQ(SP=105%GCD=1%ISR=109%TI=Z%CI=Z%II=I%T
OS:S=A)SEQ(SP=105%GCD=2%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M539ST11NW7%O2=M
OS:539ST11NW7%O3=M539NNT11NW7%O4=M539ST11NW7%O5=M539ST11NW7%O6=M539ST11)WIN
OS:(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF
OS:0%O=M539NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(
OS:R=N)T4(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T4(R=Y%DF=Y%T=40%
OS:W=0%S=O%A=Z%F=R%O=%RD=0%Q=)T5(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%R
OS:D=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=O%A=Z%F=R%O=%RD=0
OS:%Q=)T7(R=N)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G
OS:%RIPCK=G%RUCK=D5C9%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 3 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- serving web traffic on port 80
- ssh on port 22

Since it is a web server a curl command check gives us the following.

```bash
curl http://10.10.11.44
```

```html
<!DOCTYPE html PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html>
  <head>
    <title>301 Moved Permanently</title>
  </head>
  <body>
    <h1>Moved Permanently</h1>
    <p>The document has moved <a href="http://alert.htb/">here</a>.</p>
    <hr />
    <address>Apache/2.4.41 (Ubuntu) Server at 10.10.11.44 Port 80</address>
  </body>
</html>
```

Attempting directories with gobuster.

```bash
gobuster dir -u http://10.10.11.44 -w data/directory-list-2.3-medium.txt -b 301
```

```txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.44
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                data/directory-list-2.3-medium.txt
[+] Negative Status codes:   301
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/http%3A%2F%2Fwww     (Status: 404) [Size: 273]
/http%3A%2F%2Fyoutube (Status: 404) [Size: 273]
/http%3A%2F%2Fblogs   (Status: 404) [Size: 273]
/http%3A%2F%2Fblog    (Status: 404) [Size: 273]
/**http%3A%2F%2Fwww   (Status: 404) [Size: 273]
/%3FRID%3D2671        (Status: 403) [Size: 276]
/http%3A%2F%2Fcommunity (Status: 404) [Size: 273]
/http%3A%2F%2Fradar   (Status: 404) [Size: 273]
/login%3f             (Status: 403) [Size: 276]
/http%3A%2F%2Fjeremiahgrossman (Status: 404) [Size: 273]
/http%3A%2F%2Fweblog  (Status: 404) [Size: 273]
/http%3A%2F%2Fswik    (Status: 404) [Size: 273]
Progress: 220559 / 220560 (100.00%)
===============================================================
Finished
===============================================================
```
