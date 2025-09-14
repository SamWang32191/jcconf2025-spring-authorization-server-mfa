# JCConf2025 法規掰掰！Spring Authorization Server 的 OTP 整合快攻
>  在 OIDC 的認證流程中，透過客製化 Spring Authorization Server，加入第二個認證因子 (OTP)，以達成部分法規，規範登入時需要 MFA (Multi-factor Authentication) 要求的快速方案。



### Directories
```
    .
    ├── default  // --> default的SAS 
    ├── doc      // --> PPT 
    └── mfa      // --> 有2FA的SAS
```


### How to run
#### Before run, please make sure you have installed JDK 21 and Maven

#### 啟動預設沒有2FA的SAS
`mvn clean compile spring-boot:run -pl default`

#### 啟動有2FA的SAS
`mvn clean compile spring-boot:run -pl default`
`mvn clean compile spring-boot:run -pl mfa`

<img width="1782" height="1079" alt="截圖 2025-09-14 14 04 56" src="https://github.com/user-attachments/assets/244b6946-9f29-4671-8492-43afe8e7d7b5" />
