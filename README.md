[![](https://img.shields.io/badge/JCConf-2025-green?style=for-the-badge)](https://jcconf.tw/2025/)


# JCConf2025 法規掰掰！<br>Spring Authorization Server 的 OTP 整合快攻
>  在 OIDC 的認證流程中，透過客製化 Spring Authorization Server，加入第二個認證因子 (OTP)，以達成部分法規，規範登入時需要 MFA (Multi-factor Authentication) 要求的快速方案。

### References: 
[Spring-Authorization-Server Examples](https://github.com/spring-projects/spring-authorization-server/tree/1.5.x/samples/demo-authorizationserver)

### Directories
```
    .
    ├── default  // --> default的SAS 
    ├── doc      // --> PPT 
    └── mfa      // --> 有2FA的SAS
```


### How to run
> Before run, please make sure you have installed JDK 21 and Maven

#### 啟動沒有2FA的SAS
`mvn clean compile spring-boot:run -pl default` 

#### 啟動有2FA的SAS
`mvn clean compile spring-boot:run -pl mfa`

### How to test
你可以使用任意的oauth2 client來request a new token，<br>需根據測試使用的client來更換[AuthorizationServerConfig](https://github.com/SamWang32191/jcconf2025-spring-authorization-server-mfa/blob/7a6c81a986482aff90bcac50a69e66b72f560814/default/src/main/java/tw/com/example/demo/authorizationserverdemo/security/AuthorizationServerConfig.java#L88)中的client redirect uri

以下用postman 做範例，配置如下圖 
<img width="1782" height="1079" alt="截圖 2025-09-14 14 04 56" src="https://github.com/user-attachments/assets/244b6946-9f29-4671-8492-43afe8e7d7b5" />
