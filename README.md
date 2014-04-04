# Purpose

The purpose of this guide is to better educate application developers, specifically entrepreneurial, application developers and infrastructure personnel on best practices used to secure virtual currency web applications. They are based on my experiences working with payment technologies over the last 15 years.

# Personnel

This might seem like an odd place to start but just don’t skip it. Most of the other sections in this document can easily be undone by a key employee’s carelessness or malice. The application you build is only going to be as secure as the people working on it. As the understanding of application security grows more focus will be applied to ‘social engineering’ exploits opposed to technical exploits. It is fundamentally important that the individuals who have write access to your source code repository or elevated production privileges be ‘trustworthy’, in both their abilities and intentions. How you go about determining this is up to you but emphasis needs to be placed on it. It is recommended to restrict direct write access to production repositories for new hires. Have them work with experienced ‘trusted’ developers on feature branches or forks which are to be reviewed before being merged into the main repository. 

Even with trustworthy individuals in place it is still wise to enforce an N of M policy for critical aspects of the system further reducing the potential of a lone individual compromising your application. For example:

Assign N individuals to the role of ‘key custodians’. Individuals responsible for ‘unlocking’ the keys used to encrypt/decrypt data.
Every source code commit or configuration change needs to be reviewed by someone other than the original author and noted. Using feature branches with the merge into the release branch acting as sign off by the review(s) as an example.
Production code should be deployed directly from the source code repository and built on an independent ‘production’ build/deployment system. Approved source code changes should have a short, secure, audited and simple path to production servers. They shouldn’t ‘stop over’ on a workstation after being approved for deployment.

Try to ensure any inappropriate behaviour would have to involve collusion of multiple individuals to be successful. Responsibility for errors and omissions should be the responsibility of the original developer (employee, whoever) and the reviewer.

# Network

Like protective clothing, the way to approach network security is with layers. Any route into a production environment should involve crossing multiple layers, both on the way in and on the way out. Each layer should be locked down to a specific class of server performing one role, like an application server, or a database server. Don’t combine roles onto a single server. Deploying an Intrusion Protection System (IPS) between each layer that all traffic must transverse adds overhead and becomes difficult to do on some virtualized environments but if an outer layer is ever compromised you want abnormal internal traffic to light up alerts like a christmas tree.

Below is an example of a network utilizing two firewalls, an internal and an external, running intrusion protection systems. The NAT Firewall/IPS and the External Firewall/IPS could be comprised into one physical device as long as the outbound traffic restrictions mentioned below are respected. The rest of the images in this document may show several firewalls but in reality they could be combined. Having an external firewall and an internal firewall that are physically separated is still a good idea though. Having one firewall with all traffic routing through it would represent a signal point in which an attacker could gain access to everything.

# Public Interface

Historically disclosing your public IP wasn’t a big deal. Today it should be avoided at all costs. There are cases where historical information available on sites like www.domaintools.com allowed attackers to determine the hosting provider for a site, from the IP block owner, after they introduced a DDoS protection system and remotely socially engineer their way into gaining root access to a server.

Use a DDoS protection service such as Cloud Fare. They have a fantastic information on their blog such as: http://blog.cloudflare.com/ddos-prevention-protecting-the-origin. Not only do you gain DDoS protection but if you follow the information in the link you can completely hide your public IP address, removing another possible vector that could be used by an attacker. The linked post says to change your IP address after setting up with them. I would go further by saying NEVER associate your domain to your public IP. If you need to test prior to setting up with CloudFare register a throw away domain or just test with your IP. As mentioned above, the issue you have if you just change your IP address from an IP assigned to you by your hosting provider to another address assigned to you from the same hosting provider is attackers will still be able to find your provider. Let the social engineering begin...

Even with a DDoS protection service in front of your public IP a listening socket should not terminate on an internal machine that can access sensitive data.


There is a bunch of things wrong with the above diagram, it has been simplified to articulate a point, but the one in question is if an attacker can exploit the application server and gain escalated privileges they are right next door to your sensitive data. In fact they don’t need to even try to exploit the database. They probably could just mimic another connection from your application server, assuming it has the ability to read data from the database, and call it a day.

What (PCI)[#pci] and other security practices call for is a level of indirection between the internet and servers that have direct access to sensitive data. Ideally at Layer 7 of the OSI model.


In the above network, which still has many things wrong with it, there is now a level of indirection between the internet and the only server that has direct access to sensitive data. In this case the web server is running Nginx or Apache and configured to ‘proxy’ the requests back to the application server. It doesn’t have to perform any other activity like serving static content, it is just there for a level of indirection. The proxying causes the web server to open a new connection to the application server and translate the traffic between the connected internal socket and the external socket using standard HTTP. If an attacker is successful in exploiting Nginx and gains shell access over a socket they still can’t do much. Maybe snoop other traffic flowing through the server, which your host based intrusion detection (HID*) system should alert on.

# Layers

If you are reading this document in a linear fashion we now have a DDoS protection service ‘layer’ in front of our public IP address, a web server listening on the public interface before proxying requests back to our single application server which reads and writes data to our database. It is a good start and would put you in front of some of the other configurations I’ve seen over the years but in reality the system would still be highly exposed and to make matters worse if something ever happened you may never know. The attacker would most likely cover their tracks and if you did manage to determine your were exploited, say an anonymous pastebin.com post containing all your users, you would be in the dark about how it was done.

Rather than waiting for a pastebin.com to show up it is better to isolate individual server classes from each other behind firewalls running an intrustion protection system (IPS*) and only open ports between the layers for required services. For example if your application server is the only class of server that needs to talk to your database server, open just the required port between the application server network and the database server network. This should be done between every class of server. If your network has 3 different classes of servers, it should have 3 different networks that are only traversable by passing through an IPS.


In this example incoming HTTP traffic passes through a Firewall/IPS device. It actively inspects traffic looking for ‘rule violations’ and when one is detected it actively blocks the remote address and drops the connection. It is important that it also sends out alerts to ensure you are up to speed on what is happening. The web server proxies the HTTP request to the application server which passes through another Firewall/IPS combination device. The application is then able to read and write to the database by connecting through a Firewall/IPS device in much the same fashion.

# Intrusion Detection vs Intrusion Protection

Intrusion Detection Systems (IDS) typically sit independent of firewalls. They passively monitor all traffic presented to them trying to find rule matches to alert on. A common configuration for IDS is to enable port ‘monitoring’ on a switch so that all network traffic is ‘mirrored’ on an interface available to the IDS system. Once a rule match is found the IDS system sends out an alert and it is up to the alert recipients to determine the course of action to take. If your internal IDS system detects a port scan originating from your web server against your application server you better sort it out in a hurry.


In the above diagram the red arrows represent ‘mirrored’ traffic being sent to the IDS system for inspection and rule matching. The IDS would send out alerts when a rule is matched, but that is it. You would have to manually intervene to stop the ongoing threat.

An Intrusion Protection System (IPS) is effectively the same as an IDS system but instead of hanging off a monitoring switch port it is normally part of or positioned very close to firewalls. When a rule match is detected not only does the IPS system send an alert it actively blocks the source (or destination) and drops the connection based on how the rule was configured. This has advantages when something like a port scan is detected it will block the offending host and send an alert preventing anymore damage from being down, opposed to just sending an alert. I don’t think anybody will argue that taking down your site in the case a breach is a bad thing. False positives on the other hand could be problematic if you don’t fully understand the role each network is supposed to be playing.


The above diagram is the same layout as the IDS diagram above with the exception of the IPS system being deployed inline. The red arrow represents the traffic being inspected and blocked at the IPS, before it enters the rest of the network.

For payment systems (especially virtual currencies) using an IPS on all perimeter interfaces (PCI requirement) and between all internal networks is the better approach. Think of them as the bulkheads on a ship. IDS was mentioned as there doesn’t yet appear to be a good way to integrate an IPS into some virtual environments.

# Restrict Outbound

Now that we have talked about incoming connections and appropriate layering what happens if your system needs to call out to remote systems on the internet? Most people overlook the importance of closing all possible methods of egress with the exception of what is absolutely required. In some cases it might mean creating another bulkhead (network) and setting up your own equivalent internal service such as a time server or an OS package server (apt, yum, etc...). 

PCI states in section 1.3.5: 

> “Do not allow unauthorized outbound traffic from the cardholder data environment to the Internet.” 

Authorized outbound traffic should be accounted for by limiting the protocol and port that can be connected to. For example your application needs to upload reports to your bank over FTPS, your outbound firewall should disallow all egress traffic except for FTPS to your bank’s FTP server originating from your application server network. The general idea is that if somebody manages to compromise enough layers of your network and discovers something of value they are going to try to copy it out of your network. If the only possible destinations allowed by your outbound firewall are to known services this becomes harder for them. You still need to make wise decisions though. For example if your system allowed users to export their reports to their DropBox account you may want to apply a level of indirection here, opposed to allowing the application server network to communicate with DropBox’s IP addresses over SSL. Your IPS system wouldn’t be able to tell if the traffic was normal or if an attacker was running off with all your user’s email addresses.

Never use the same IP address as your web server for outbound connections. All traffic originating from within your production environment should egress out through a different public IP address. Ideally an IP address in which there are no listening services.


The above diagram contains just as many firewalls as it does other systems. In reality they don’t need to be physically separate firewalls but it is a good idea. If you want to go completely paranoid use a different firewall manufacturer at each level in case an exploit is discovered in one of them. 

# Sending Email

I was going to mention this is the above section on restricting outbound traffic but I feel it needs a bit more attention. There are a few things to be cautious of when sending emails. 

Use an external SMTP provider such as SendGrid or MailGun and send email’s using their REST services to avoid unnecessary email headers such as ‘Received’ from disclosing information about your environment such as your outbound firewall’s public IP address. It is also important to check for bounces using their web hooks and act accordingly, i.e. automatically disable/alert on login for accounts in which email can no longer be delivered.

As with all outbound traffic originating from your production environment, none should egress out through the web server’s IP address.

# Management Console

A management console is a controlled entry point into the secure production environment used for maintenance and other authorized activities. In order to directly access a system or firewall within the environment, other than how the application is supposed to function, a user (i.e. production support, release management, etc…) must connect and login using their unique credentials; ideally 2-factor. All access, authorized or not, should immediately send an alert. All authorized activities should be known before an alert is triggered. All activity should be logged.

It is possible to make the management console an extension of your office or other ‘privileged location’ but it becomes easy to blur the lines of where one environment starts and the other stops. I’m a fan of enforcing a VPN connection with individually issued certificates in order to connect to the management console, even from a ‘privileged location’. This makes it easy to see the distinction between the production environment and others as well as provides quick 2-factor authentication.

# Hosts

Hosting your application on popular open source software is preferred. Even if you don’t need access to the source code you are able to benefit from a community that shares your concerns on security (hopefully). There are several hardening guides available on the internet depending on your operating system of choice. Each will contain a bunch of suggestions on how to secure the OS from unauthorized access. The core of each list will contain things like:

Disable unused services
i.e. nsfd, portmap, etc...
Remove unused software packages
i.e. mysql, X, KDE, etc...
Disable direct root/admin login
Disable all shared accounts
Enforce long passwords
http://xkcd.com/936/

It is also a good idea to use a host based intrusion detection (HID*) system like OSSEC to monitor files and running services on individual servers for changes. It requires some setup but it is worth knowing when an important file changes without your knowledge.

# Authentication

Passwords is area where PCI falls down in my opinion. In ‘Requirement 8: Assign a unique ID to each person with computer access’ they state the following:

> 8.5.9 Change user passwords at least every 90 days.

 * Changing a secure password every 90 days is ridiculous. If a password is sufficiently secure (i.e. long) and not reused anywhere else it should be secure for longer than the person will live. Forcing people to forget, create and memorize a new password every 90 days results in lots of variations on the same password and lots of sticky notes stuck to monitors. 

> 8.5.10 Require a minimum password length of at least seven characters. 

 * A seven character password could be brute forced in seconds if the data was ever stolen in a breach. oclHashcat can attempt thousands to millions of guesses each second depending on the number of GPU’s and the algorithm used. 
 * 12+ characters or longer if possible. 

> 8.5.11 Use passwords containing both numeric and alphabetic characters.

 * Allow users to enter in any printable characters for their password, including spaces, but enforcing longer passwords increases entropy without forcing the user to remember odd punctuation placement. Again, see: http://xkcd.com/936/ 

>8.5.12 Do not allow an individual to submit a new password that is the same as any of the last four passwords he or she has used.

 * Not really an issue if you aren’t forcing the user to change the password every 90 days. 
 * Who doesn’t just increment the number at the end by one anyway? 
 * MyPassword1, MyPassword2, etc... 

Don’t share accounts. Your services can run as a unique user but multiple people shouldn’t be logging in as www or any other shared account. Users should login with their own accounts. Once logged in authorized users could use sudo or other privilege escalation mechanisms. Rootsh* works well on Unix based systems to capture users sessions when they request root access. All session commands are sent to logs for archival and review if needed, although sometimes they can be tricky to understand due to control keys being used. Running rootsh on all production servers is ideal.

As your environment grows having a centralized authentication server eases administration. Creating another class of server hosting OpenLDAP or a similar service in which all servers in the production environment rely on for authentication helps when adding or removing users to the environment. If a central authentication server is used make sure it is locked down like all other hosts in the production environment. Only authorized users should be allowed to add, modify or remove users and permissions. Alerting for any change, authorized or not, is also a good idea.

# Patches

Apply patches frequently. How frequently depends on your scenario. PCI and other security programs want policies in place for regular updates and security patches. With most modern operating systems providing package management and updates it makes this fairly easy as long as it is monitored. Check for security updates daily and apply them based on their impact to your system. Sooner is almost always better.

# Encryption

All sensitive ‘data at rest’ should be encrypted in some fashion, AES 256, one way hashing, etc... Actually performing the encryption is relatively easy, the hard part is key management. Too many people that think running everything out of an encrypted partition that is mounted at boot time based on the correct passphrase being entered is sufficient. It is not. What happens when you fire the individual who knows the passphrase? Who entered the passphrase last? What happens if the machine is compromised while the partition is mounted?

Encryption is less about the data and more about the management of it. What works well is ‘remote encryption’. An additional class of servers, segregated like any other class of servers, with access controls in place to ensure the application or users are only able to request the encryption or decryption of data they are allowed to access. The encryption server only stores the private keys, not the data. The encryption server responds to remote encryption calls by verifying the requesting party by credentials, certificate, or both and returns the encrypted data and the id of the private key used; not the actual private key. The private keys never leave the encryption server with the exception of disaster recovery scenarios. Decryption calls are handled the same, the id of the key stored when the data was encrypted and the encrypted data. The encryption server verifies the credentials and responds accordinging to the decryption request. The encryption server should also change the keys used every N number of encryption requests. This limits the impact of having to re-encrypt sensitive data if a backup volume was breached or if a key individual was dismissed.

Using this approach all sensitive data stored in your application’s database is encrypted at the ‘field’ or ‘column’ level and only authorized calls from the application can decrypt it. Monitoring the encryption server for usage can also be an indicator of a breach. It is worth pointing out that there is currently no good open source implementation of this type of encryption server. Historically they have been built in house.

# Key Custodians

The concept of ‘Key Custodians’ are directly out of PCI compliance (and NIST*). They are people in your organization who have the added role of memorizing a unique passphrase used by the encryption server when it is started. Ideally there are N key custodians and the encryption server would only require N-1 (or similar) passphrases to be entered on application start in order to unlock the other keys for use.

# Logging

Centralizing, reviewing and alerting on events that happen within your production environment is key in ensuring a secure application. Logs also need to be protected from manipulation as it is a common technique of attackers to attempt to delete logs in order to cover up their tracks. Immediately copying logs off servers to a protected centralized log server using something like syslog (rsyslog, ksyslog, etc…) and Log-o* works well.

Never log sensitive data like passwords, private keys, etc...

It is also important to review logs but rather than waiting to review them it is better to make the ‘tailing’ of logs a normal activity in your organization. People are very good at recognizing patterns and after a few weeks of tailing logs in a secondary window, dashboard, etc… they will have a good understanding of normal activity versus abnormal.

Sending out alerts on key events is only useful if you have a plan on how to deal with them. If the production database is logged into by a member of your organization, somebody should be following up (ideally before they logged in) as to what they are doing. Sending out alerts on exceptions and errors is also important. An HTTP 404 might not seem like a big deal but it is better to be made aware of somebody snooping around your site opposed to ignoring it.

# Timeserver

Every system on your network needs to sync their clocks against a timeserver. PCI wants you to host your own time servers and configure all other servers to use them. They are allowed to sync to external pools permitted by your outbound firewall.

# Application

The Open Web Application Security Project (OWASP) is a good resource for guidelines on how to build a secure application. They have recently updated their ‘top 10’ exploit list with examples on how to protect against them. Regardless of guidelines and policies it comes down to you to know the frameworks, technology, and most importantly the code you write to build your application and how they can be exploited. All developers on your team should be familiar with the OWASP top 10 and the development environment/frameworks used should make doing ‘the secure thing’ the default, opposed to forcing developers to repeat themselves every time to enforce security. i.e. scrubbing form inputs.

## Content Distribution Networks

At one time I was a huge fan of CDN’s. I wondered why anybody would ever host any static content on their own webserver when they were able to include Bootstrap from //www.bootstrapcdn.com or JQuery from //cdnjs.com (note the missing protocol). If every application included their static resources from the same CDN your users would be met with faster page load times because JQuery, Bootstrap, or whatever would be loaded from their browser cache. Seems to make sense. Except you have no idea what security precautions those CDN’s have in place. It isn’t unreasonable to think that as a CDN grows in popularity it wouldn’t become a target for malicious individuals. Especially if the stakes are high enough.

I’ve recently dropped using CDN’s from anything I’ve done recently and started to deploy an everything.js and an everything.css file which are concatenated and minified versions of all the libraries the system requires. It gives you more control over caching and removes a possible vector of attack. You have to apply some intelligence in your own scenario to get page speed up. Don’t just drop a spinner in the middle of the page for 2.5 seconds...

## Passwords

The information in the Hosts section on passwords is applicable to your application as well. Try encourage the use of long passphrases, 12+ chars long and don’t limit what characters they can use. Recent studies have shown that password strength meters help encourage users to pick stronger passwords. Dropbox has a fantastic strength meter called zxcvbn*.

Use something like PBKDF2, bcrypt, or scrypt for stored passwords. PBKDF2 seems to be falling out of favour recently due it’s ability to be run efficiently on GPU’s.

## 2-Factor

Depending on the nature of your application 2-Factor authentication might be optional. If you are doing anything in the virtual currency space I think the time has come to make 2-Factor mandatory on signup. With the prevalence of phones capable of receiving SMS messages I’m disappointed in how few sites enforce mandatory 2-Factor authentication. You don’t need to enforce 2-Factor all the time, just at points in the application where an attacker would seek to defraud, hijack, destroy, or otherwise compromise your application or your users. When sending funds, changing email, password, cell phone number, etc... The important part is enabling 2-Factor by default and making it known it is for the users protection and nothing else.

## Notifications

This has finally started to pick up steam but it still isn’t consistent. Whenever an action is taken by a user that is deemed to be of consequence send them a notification, email, SMS, mobile app, whatever. If the user has made the change themselves they ignore it, but if they didn’t it will spur them into action to quell the issue shortly after it happened and not 2 weeks later when they finally login. Send notifications to both the new and the old email if they are performing an email change, both phones if changing numbers, etc...

## GeoIP

In many cases it makes sense to determine where an individual is accessing your site from and use historical records to determine the probability of the account being accessed by another party. For example if the user has logged in from Canada for the last 10 times then all of sudden they login from the US, it might be wise to consider that login suspicious. I’m also a huge fan of Tor but if you are providing a service that requires performing KYC on individuals and companies blocking known Tor exit nodes also makes sense in order to protect your customers from phishing attacks and unauthorized logins.

# Physical

If you are hosting physical hardware yourself it is important to restrict access in order to eliminate attacks originating from within the data center. No amount of intrusion protection will help if somebody is allowed to plug something into your servers or network without your knowledge.

Disable any unused hardware such as USB or ethernet ports in servers and switches. Don’t give one person full authority over your hardware, it is better to have multiple people responsible for each others actions in order to eliminate an individual acting alone. Always try to ensure people will have to collude with each other in order to comprise any aspect of your system.

# Wallets

Don’t put your hot wallet on your web server or application server. Place it on it’s own class of servers within it’s own network isolated from each other like everything else. If you are using the standard daemons (bitcoind, litecoind, etc…) enable SSL on the RPC requests. Encrypt the private keys on disk and require manual intervention on system start to decrypt them. In this case disk encryption would suffice as you aren’t trying to protect the keys from use when the system is running, you are protecting the keys if somebody was to steal the server; or socially engineer your Tier 1 hosting provider into rebooting the server and giving root console access over the phone to an unknown third party.

It isn’t stated anywhere (yet) but your virtual currency business should be able to cover the loss of a stolen hot wallet. If you do ‘cold wallets’ correctly there should be no risk of loss.

BIP32 - Hierarchical Deterministic Wallets are currently the safest way to support Bitcoin cold wallets. There is support for other alt currencies* as well but you are going to have to work for it. Armory has a nice breakdown of how to do offline/online wallets with their software here: https://bitcoinarmory.com/about/using-our-wallet/.

# Blockchain

If you are going to be sending and receiving transactions it may make sense to run nodes on the virtual currency networks you support and use something like Abe* to query/investigate the blockchain opposed to using a third party service.

# Bug Bounty

Create a bug bounty program that rewards submissions as well as defines timelines for disclosure. Something like 90 days to give you enough time to investigate. It sets a level of commitment to the community and buys you some time to fix the issue.

# Secrecy

Don’t disclose any details about your infrastructure publicly, ever. This includes network diagrams, routers, switches, firewalls, etc... Make sure any information posted to StackExchange, Github, etc… doesn’t disclose any important details about the internal workings or policies of your application or organization. You never know what details attackers will find useful. This is easy said than done but unless you plan to fully open source something very little good can come of leaking information out. Don’t worry about web server’s disclosing themselves or high level frameworks in use by your system. It doesn’t take long to figure out a webpage is using JQuery. Just don’t disclose things that aren’t normally disclosed or available by inspecting web pages or headers, like your kernel version or what type of database you run.

# Don’t Poke The Bear

Silly this has to be mentioned, but be humble. Don’t run your mouth on forums talking about how superior your service/application/product is. It only isolates the community further and no good can come from it. In fact if you set yourself up as an ass people will come out of the woodwork just to take a run at you. You have everything to lose and they have everything to gain.

Nobody likes a blow hard.

# Resources

### rootsh
 * Root Shell
 * Logs all shell commands and output to log files
 * http://sourceforge.net/projects/rootsh/
 
### Snort
 * Open source network intrusion prevention (IPS) and intrustion detection (IDS) system.
 * http://snort.org/
 
### OWASP
Open Web Application Security Project
https://www.owasp.org/

### PCI
 * Payment Card Industry Standards Association
 * Visa, Mastercard, JCB, etc…
 * Through but at times flawed or dated application security policies and procedures
 * https://www.pcisecuritystandards.org/

### NIST
 * National Institute of Standards and Technology
 * http://csrc.nist.gov/ - Computer Security Division
 
### NIST SP 800-130
 * A Framework for Designing Cryptographic Key Management Systems
 * http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-130.pdf
 
### Does My Password Go up to Eleven? The Impact of Password Meters on Password Selection
 * Arstechnica summary: http://arstechnica.com/security/2013/05/its-official-password-strength-meters-arent-security-theater/
 * Paper: https://research.microsoft.com/pubs/192108/chi13b.pdf

### zxcvbn
 * zxcvbn: realistic password strength estimation: https://tech.dropbox.com/2012/04/zxcvbn-realistic-password-strength-estimation/
 * https://github.com/dropbox/zxcvbn
 
### PBKDF2
 * http://tools.ietf.org/html/rfc2898
 
### bcrypt
 * http://bcrypt.sourceforge.net/
 
### scrypt
 * http://www.tarsnap.com/scrypt.html
 
### Log-o
 * Nodejs centralized centralized syslog server
 * https://github.com/stancarney/log-o
 * https://github.com/stancarney/log-o-client
 
### BIP32
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * http://bip32.org/
 
### Abe
 * https://github.com/bitcoin-abe/bitcoin-abe
