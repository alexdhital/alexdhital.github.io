---
cover: https://i.postimg.cc/XYBPQrL8/passw-ord-cracking.png
title: "Advanced Password Cracking: Techniques and Tools for Red Teamers and Pentesters"
date: 7/18/2024 9:30:00 +06:00
categories: research
tags: [Password Cracking, Hashcat]
toc: true
toc_number: false
---

## OverView
Whether you're a penetration tester, red teamer, CTF player, or cybersecurity enthusiast, you're likely familiar with the concept of password cracking. It is a vital skill for any offensive security practitioner. In the past, passwords were often stored in plaintext or with weak hashing algorithms like MD5. Back then, it was common to dump a database via SQL injection, feed the hashes into [Crackstation](https://crackstation.net), and easily recover the plaintext passwords. Remember those days? Well password hashing and encryption have come a long way since then with algorithms and better practices making the process more challenging. During penetration tests or red team engagements it is common that we may find various hashes which may include MD5, NTLM, SHA-256, Bcrypt, etc.

***Note:*** Encoding is the process of converting a data from one format to another usually for storing or transferring data in proper format. It is not for ensuring protection of data. Encryption is the process of converting a plaintext information into ciphertext using an algorithm and a key. This ciphertext can then be decrypted back using the same key. Hashing is the process of converting data into a fixed size characters/values using a hash function which is irreversble meaning it cannot be converted back to original message. The only way is to verify the hash is to compare it to a new hash of the same data.

## Cracking Hashes with Wordlists
Two of the most sought after tools when it comes to password cracking is [Hashcat](https://hashcat.net/hashcat/) and [John The Ripper](https://www.openwall.com/john/). As with the recent [Rockyou2024.txt](https://github.com/hkphh/rockyou2024.txt) which is approximately 160 GB, It can significantly enchance the capability of successfully cracking password hashes. Lets take an example during a penetration test we successfully dumped ntlm hash from one of the workstations of a user via same old `sekurlsa::logonpasswords`. We can simply use hashcat and try every single combination of password in the worslist. Hashcat will convert every single password candidate into its ntlm format and compare with our given hash value if a match is found the password is cracked. Below `-a` is the attack mode and `-m` is the hash mode.

```bash
┌──(alex㉿kali)-[~]
└─$ hashcat -a 0 -m 1000 hash /usr/share/wordlists/rockyou.txt --show

59fc0f884922b4ce376051134c71e22c:Qwerty123
```

If the hash is unknown [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) has a nice table view of hash mode, hash name and example hashes.

## Cracking hashes with wordlists and rules
Organizations often use password combinations of `{OrganizationName}{Year}` like `Microsoft2024`. In my college the WIFI password as well as all the student workstation password was `Islington2024`. Rules are ways of manipluating or extending the base words in a wordlist that are common habits for users or organizations. For example the word `Islington` may exist in wordlist we can extend this by replacing with uppercase letters, character replacement eg: `S` => `$`, `a` => `@`, prepending characters like `!Islington` or appending characters like `Islington2024`.

```bash
┌──(alex㉿kali)-[~]
└─$ hashcat -a 0 -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -r rules/add-year.rule --show

924cf964a570e64109e8ef68aea070d1:spring2024
```

**Note:** Hashcat ships with lots of rule files in the rules directory that we can use.

We can create our own rules. [hashcat-rules](https://hashcat.net/wiki/doku.php?id=rule_based_attack) Lets imagine a scenario we are on a penetration test for a company `astrosoft`. From open source intelligence or previous data breach we found that they might be using characters like `@` in place of `a`, `$` in place of `s`, `0` in place of `o` and `year` appended for most of their passwords. We can simply create a rule file as below.

```bash
┌──(alex㉿kali)-[~]
└─$ cat rules/company.rule 
c sa@ so0 ss$ $2$0$2$4
```

Above `c` is to capitalize the first letter, `sa@` means to substitute a with @, `so0` means to substitute o with 0 and append `2024` at the end. `36CFEC3D295BDC66AE9DBD059E498C12` this will be the ntlm hash which I will be cracking with some custom made wordlists as below.

```bash                                                                                                                                                                                        
┌──(alex㉿kali)-[~]
└─$ cat wordlists.txt 
summer
winter
qwerty
ancestor
astrosoft
Safe
shampoo
```
Using hashcat with the custom generated rules we successfully cracked the hash to retrieve plaintext password as `A$tr0$0ft2024`.

```bash
┌──(alex㉿kali)-[~]
└─$ hashcat -a 0 -m 1000 ntlm-hash.txt wordlists.txt -r rules/company.rule --show

36cfec3d295bdc66ae9dbd059e498c12:A$tr0$0ft2024
```

## Cracking hashes with wordlists and masks
Masks are subset of bruteforce attacks where we know the position of characterset in pasword. Let's suppose we have ntlm hash of a user `59FC0F884922B4CE376051134C71E22C`, During reconnaissance phase we found that according to company policy the user accounts passwords is 9 characters in total, should begin with an uppercase character followed by 5 lowercase characters followed by 3 digits. We can use masks attacks in hashcat as below. This attack is usually very fast.

```bash                    
┌──(alex㉿kali)-[~]
└─$ hashcat -a 3 -m 1000 hash.txt ?u?l?l?l?l?l?d?d?d --show

59fc0f884922b4ce376051134c71e22c:Qwerty123
```

We can also set custom characterset for example: for the hash `07FCF2503320D74A55DE1E53EF835DB0` we know that the password length will be 7 characters last two characters can be either a digit or a special character. We can create our custom characterset like we create a custom charset 1 which resembles either a digit or a special character.

```bash                        
┌──(alex㉿kali)-[~]
└─$ hashcat -a 3 -m 1000 hash.txt -1 ?d?s ?u?l?l?l?l?l?1 --show

59fc0f884922b4ce376051134c71e22c:Winter!
```
In above scenario we knew the password length but what if we didnot know the length of password beforehand. We just know that maximum password length is 12, password starts with uppercase letter and may contain digits or special characters at the end.  We can create a custom `.hcmask` file with different lengths. eg `test.hcmask`

```bash
┌──(alex㉿kali)-[~]
└─$ cat test.hcmask                                   

?d?s,?u?l?l?l?l?1
?d?s,?u?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?l?1
?d?s,?u?l?l?l?l?l?l?l?l?l?l?1
```
Above, We generated an `hcmask` file with different lengths upto total length 12. Suppose our ntlm hash is `1501F896CAE1FD4F0BF6B9593E81DEA3`. We know that the maximum password length is 12 or can be less, initial character is uppercase followed by lowercase letters and digit or special character at end. We can use hashcat with above hcmask file.

```bash
┌──(alex㉿kali)-[~]
└─$ hashcat -a 3 -m 1000 hash.txt test.hcmask --show

1501F896CAE1FD4F0BF6B9593E81DEA3:Christopher1
```
We can also define static string in masks suppose we find out the password includes the company name with digits appended but we donot know the length of digits in thise case we can create a mask as below. 

```bash
┌──(alex㉿kali)-[~]
└─$ cat company.hcmask 
Astrosoft?d
Astrosoft?d?d
Astrosoft?d?d?d
Astrosoft?d?d?d?d
Astrosoft?d?d?d?d?d
```
## Hashcat Hybrid attacks
The attack mode 6 and 7 are used for combination of wordlists and masks. For example while bruteforcing ntlm hash we need to append `?d?d?d?d` digits at the end of each word in the wordlist using attack mode 6 we can do so as below.

```bash                     
┌──(alex㉿kali)-[~]
└─$ hashcat -a 6 -m 1000 ntlm-hash.txt /usr/share/wordlists/rockyou.txt ?d?d?d?d --show

349c161a3eb493c6347292a58528f923:Summer2024                       
```
Similarly if we want to prepend any character, digits or special characters with wordlists we can use attack mode 7 to do so. Here, we are prepending `?d?d?d?d` digits before each word in the wordlist.

```bash
┌──(alex㉿kali)-[/tmp]
└─$ hashcat -a 7 -m 1000 ntlm-hash.txt /usr/share/wordlists/rockyou.txt ?d?d?d?d --show

E137D7C5AF09F19AC20158E8AC271FFA:2024winter
```
## Converting Password-Protected Files to Hashes for Cracking with John
Often we find files such as zip archive, KeePass kdbx files, PDF files, MS office files, ssh private keys, etherium wallet files, etc which are encrypted and required valid password to access them. [*2john suite](https://github.com/openwall/john/tree/bleeding-jumbo/run) has collection of scripts which can be used to convert these encrypted files into respective hash format which can then be passed to [John The Ripper](https://www.openwall.com/john/) for cracking. John will automatically identity the hash format and attempt to crack it using our supplied wordlist. Below are some examples of converting these encrypted files to hash formats and cracking them using John the Ripper:

1. **ZIP Files**
```bash
zip2john protected.zip > ziphash.txt
john --wordlist=wordlist.txt ziphash.txt
```
2. **KeePass KDBX Files**
```bash
keepass2john database.kdbx > keepasshash.txt
john --wordlist=wordlist.txt keepasshash.txt
```
3. **PDF Files**
```bash
pdf2john.pl protected.pdf > pdfhash.txt
john --wordlist=wordlist.txt pdfhash.txt
```
4. **MS Office Files**
```bash
office2john protected.docx > officehash.txt
john --wordlist=wordlist.txt officehash.txt
```
5. **SSH Private Key**
```bash
ssh2john id_rsa > sshhash.txt
john --wordlist=wordlist.txt sshhash.txt
```
6. **Etherium Wallet Files**
```bash
ethereum2john wallet.json > ethhash.txt
john --wordlist=wordlist.txt ethhash.txt
```
7. **Mozilla Firefox Master Password**
```bash
mozilla2john key3.db > mozillahash.txt
john --wordlist=wordlist.txt mozillahash.txt
```
8. **LUKS Encrypted Partition**
```bash
luks2john /dev/sdaX > lukshash.txt
john --wordlist=wordlist.txt lukshash.txt
```
