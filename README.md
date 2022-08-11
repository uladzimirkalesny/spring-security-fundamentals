# Spring Security Fundamentals:

## Preconditions:

- Module # 1 - Managing Users
```shell
git checkout spring-security-1-managing-users
```
Theoretic Part:
<br/>
<ul>
<u>Authentication</u>
<li>Authentication used to verify the identity of a registered user.</li>
<li>Authentication is the process of verifying credentials: user ID (name, email address, phone number) and password.</li>
<li>Authentication types: HTTP Basic, CERT, JWT (OAuth2)</li>
<li>https never using with HttpBasic</li>
<li>HttpHeader Key: Autherization, Value: Basic Base64-encoded pwd by default (if make decode we obtain user: uuid-pwd)</li>
</ul>
<ul>
<u>Authorization</u>
<li>Authorization determines whether the verified person has access to certain resources: information, files, database.</li>
<li>The authentication factors required for authorization may vary depending on the level of security.</li>
<li>Authorization may be : webapps/HttpFilters and non-webapps/Aspect</li>
<li>Aspect can be with webapps</li>
</ul>
<ul>
<u>Glossary</u>
<li>Encoding: math function - no need secret - that transform input to output using defining rules (Base64 rule for example)</li>
<li>Encryption: transform input to output but if we want to get input from output we are need secret</li>
<li>Hash-Function: transform input to output, but we're never going from output to input (this is impossible). If we lost output, fraud never obtain output. MD5 - deprecated has collision</li>
<li>Authority: You have (read, write, delete) - other words authorities it is an action</li>
<li>Role: You are (admin, user, guest) - other words roles it is badge</li>
<li>GrantedAuthority: interface ( Authortity + Role ) - what is user allow to do</li>
<li>UserDetailsService - Core interface in Spring Security framework, which is used to retrieve the user's authentication and authorization information. It is a contract between Spring Security framework and application. This interface has only one method named loadUserByUsername() that return UserDetails</li>
<li>UserDetails - Provides core user information.</li>
<li>InMemoryUserDetailsManager - implements UserDetailsService to provide support for username/password based authentication that is stored in memory.</li>

UserDetails user = User.builder().username("user").password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW").roles("USER").build();
UserDetails admin = User.builder().username("admin").password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW").roles("USER", "ADMIN").build(); 
return new InMemoryUserDetailsManager(user, admin);

<li>PasswordEncoder - PasswordEncoder that is defined in the Spring Security configuration to encode the password. In this example, the passwords are encoded with the bcrypt algorithm because we set the PasswordEncoder as the password encoder in the configuration. BCryptPasswordEncoder / NoOpPasswordEncoder</li>
<li>Realm - an object that manages a set of users, credentials, roles, and groups</li>
</ul>
Coding Parts
<br/>
1. Configure H2 TCP server:

```java
@Bean(initMethod = "start", destroyMethod = "stop")
public Server inMemoryH2DatabaseServer()throws SQLException{
    return Server.createTcpServer("-tcp","-tcpAllowOthers","-tcpPort","9092");
}
```

2. Configure H2 Datasource and JPA:

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:spring-security
    driver-class-name: org.h2.Driver
    username: sa
    password:
  jpa:
    hibernate:
      ddl-auto: none
    open-in-view: false
    show-sql: true
    properties:
      hibernate:
        format_sql: true
  sql:
    init:
      schema-locations: classpath:database/schema.sql
      data-locations: classpath:database/data.sql
```

3. Configure Remote Connection to H2 Database via Database Tools

```java
jdbc:h2:tcp://localhost:9092/mem:spring-security
```