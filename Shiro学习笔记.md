# Shiro 学习笔记

## 什么是Shrio

Apache Shiro是一个强大而灵活的开源安全框架，他干净利落的处理身份认证，授权，企业回话管理和加密。

## Shrio能干什么

- 验证用户来核实他们的身份
- 对用户执行访问控制，如
  - 判断用户是否被分配了一个确定的安全角色
  - 判断用户是否被允许做某事

- 在任何环境下谁用 Session API ,即使没有Web或EJB容器
- 在身份验证，访问控制期间或在会话的生命周期， 对事件作出反应
- 聚集一个或多个用户安全数据的数据源，并作为一个单一的复合用户“视图”
- 启用单点登录（SSO) 功能
- 为没有关联到登录的用户启用 “Remember Me” 服务
- ·························

## Shrio框架重点组成

[![1553063657651f3b54.png](https://miao.su/images/2019/03/21/1553063657651f3b54.png)](https://miao.su/image/V6QEH)

### Shrio主要模块说明

- **Authentication : **这是一个证明用户是他们所说的他们是谁的行为，简而言之就是登录功能
- **Authorization** ：访问控制的过程，也就是绝对 "谁" 去访问 “什么”
- **Session Management ：**通过用户特定的会话，即使在非web或EJB应用程序
- **Cryptography ：**通过加密算法保持数据安全同时易于使用

### Shrio拓展功能说明

- **Web Support ：**Shrio的web支持的API能够轻松的帮助保护web应用程序
- **Caching ：**缓存是Apache Shiro 中的第一层公民，来确保安全操作快速而高效
- **Concurrency ：**Apache Shiro 利用他的并发特性来支持多线程应用程序
- **Testing**：测试支持的存在来帮助你编写单元测试和集成测试，并确保你的能够如预期的一样安全
- **“Run As” ：**一个允许用户假设为另一个用户身份（如果允许）的功能，有时候在管理脚本中很有用
- **“Remember Me” ：**在会话中记住用户的身份，所以他们只需要在强制时候登录

### Shiro 架构图

[![1553064696851f6d03.png](https://miao.su/images/2019/03/21/1553064696851f6d03.png)](https://miao.su/image/V6gZb)

[![15530647456524c4c9.png](https://miao.su/images/2019/03/21/15530647456524c4c9.png)](https://miao.su/image/V6n3R)

### Shiro所需要的Jar包

```xml
<!-- https://mvnrepository.com/artifact/org.apache.shiro/shiro-core -->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.4.0</version>
</dependency>
<!-- https://mvnrepository.com/artifact/org.slf4j/slf4j-simple -->
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-simple</artifactId>
    <version>1.7.25</version>
    <scope>test</scope>
</dependency>
```

> 注：在以上jar包中添加了日志依赖，配置如下

```properties
//TODO
```

## 身份验证

### 代码案例

```java
//测试用例，模拟安全数据，
SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();
@Before
public void serRalm(){
    simpleAccountRealm.addAccount("xuzhi","123");
}

@Test
public void test1(){
    //1、构建SecurityManager环境,并添加测试数据=》通过SimpleAccountRealm类
    DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
    //将安全数据置入SecurityManager类中，以便进行验证
    defaultSecurityManager.setRealm(simpleAccountRealm);

    //2、将SecurityManager添加到到运行环境中
    SecurityUtils.setSecurityManager(defaultSecurityManager);

    //3、通过SecurityUtils工具类获得Subject主体对象
    Subject subject = SecurityUtils.getSubject();

    //4、通过UsernamePasswordToken传入 principals/credentials ,即用户名/密码
    //这里的 username 和 password 指的是用户登录时输入的用户名和密码，例如表单中提交过来的
    UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("xuzhi","123");

    //5、调用Subject的login()方法，执行登录操作
    subject.login(usernamePasswordToken);

    // Subject 的 isAuthenticated()方法是判断用户是否已经登录
    //如果登录失败会抛出相应AuthenticationException异常，一般都是使用 try..catch 来处理登录异常
    if(subject.isAuthenticated()){
        System.out.println("登录成功");
    }

    // 登出用户
    subject.logout();
}
```

### 身份验证的步骤

1. 收集用户身份/凭证，即用户名/密码
2. 调用 Subject.login() 进行登录，如果失败将得到相应的 AuthenticationException 异常，根据异常提示用户错误信息，否则登录成功，异常信息如下
3. 最后调用Subject.logout() 进行退出操作

### 抛出异常说明

- **AuthenticationException ：**认证失败抛出的所有异常的父类，所有的异常都继承于此
- **DisabledAccountException：**禁用的账号
- **LockedAccountException**：锁定的账号
- **UnknownAccountException：**错误的账号
- **ExcessiveAttemptsException：**登录失败次数过多
- **IncorrectCredentialsException：**错误的凭证
- **ExpiredCredentialsException：**过期的凭证

### 身份认证流程

[![155306665532743719.png](https://miao.su/images/2019/03/21/155306665532743719.png)](https://miao.su/image/VX04w)

流程如下

1. 首先调用 Subject.login(token) 进行登录，其自动委托给SecurityManager，调用之前必须通过SecurityUtils.setSecurityManager() 设置；
2. SecurityManager负责真正的身份验证逻辑，他会委托给Authenticator进行身份验证
3. Authenticator 才是真正的身份验证着，Shiro API中核心的身份真正入口点，此处可以自定义插入自己的实现
4. Authenticator 可能会委托给相应的 AuthenticationStrategy 进行多 Realm 身份认证，默认 ModularRealmAuthenticator 会调用 AuthenticationStrategy 进行多 Realm 身份验证
5. Authenticator 会把相应的 token 传入 Realm ，从 Realm 获取身份验证信息，如果没有返回/抛出异常表示身份验证失败，此处可以配置多个 Realm，将按照相应的顺序及策略进行访问

## 身份授权

### 代码案例

```java
//测试用例，模拟安全数据，
SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();
SimpleAccountRealm s1 = new SimpleAccountRealm();
@Before
public void serRalm(){
    //在Realm中添加了username、password，还添加了一个权限 =》 admin
    simpleAccountRealm.addAccount("xuzhi","123","admin");
    //        s1.addAccount("admin","123");
}

@Test
public void test1(){
    //1、构建SecurityManager环境,并添加测试数据=》通过SimpleAccountRealm类
    DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
    //将安全数据置入SecurityManager类中，以便进行验证
    //        List<Realm> list = new ArrayList<>();
    //        list.add(simpleAccountRealm);
    //        list.add(s1);
    defaultSecurityManager.setRealm(simpleAccountRealm);
    //        defaultSecurityManager.setRealms(list);

    //2、将SecurityManager添加到到运行环境中
    SecurityUtils.setSecurityManager(defaultSecurityManager);

    //3、通过SecurityUtils工具类获得Subject主体对象
    Subject subject = SecurityUtils.getSubject();

    //4、通过UsernamePasswordToken传入 principals/credentials ,即用户名/密码
    //这里的 username 和 password 指的是用户登录时输入的用户名和密码，例如表单中提交过来的
    UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("admin","123");

    //5、调用Subject的login()方法，执行登录操作
    subject.login(usernamePasswordToken);

    // Subject 的 isAuthenticated()方法是判断用户是否已经认证成功
    //如果登录失败会抛出相应 AuthenticationException 异常，一般都是使用 try..catch 来处理认证异常
    if(subject.isAuthenticated()){
        System.out.println(subject.getPrincipals());
        System.out.println("登录成功");
    }
    if (subject.hasRole("admin")){
        System.out.println("改用户具有admin权限");
    }else{
        System.out.println("该用户没有admin权限");
    }

    //检查的用户是否有参数内的权限，如果没有则抛出相应异常
    subject.checkRole("admmin1");
}
```

> 如果认证的用户没有该权限则抛出相应异常，例如上面的Demo中，在Realm中的xuzhi用户具有admin权限，但是在Subject.checkRole("admin1") 中验证的是该用户是否具有admin1这个权限，因为没有所以抛出以下异常
>
> 注：Subject.checkRole() 没有返回值，Subject.hasRole() 返回一个boolean的返回值

```java
org.apache.shiro.authz.UnauthorizedException: Subject does not have role [admmin1]
```

### 授权流程

[![1553073989351f541b.png](https://miao.su/images/2019/03/21/1553073989351f541b.png)](https://miao.su/image/VX4q7)

流程如下：

1. 首先调用Subject.isPermitted*/hasRole * 接口，其会委托SecurityManager，而SecurityManager 接着会委托给Authorizer；
2. Authorizer 是真正的授权者，如果我们调用如 isPermitted("user:view")，其首先会通过 PermissionResolver把字符串转换成相应的 Permission 实例；
3. 在进行授权之前，其会调用相应的 Realm 获取 Subject 相应的角色/权限用于匹配传入的角色/权限
4. Authorizer 会判断 Realm 的角色/权限是否和传入的匹配，如果有多个 Realm ，会委托给 ModularRealmAuthorizer 进行循环判断，如果匹配如 isPermitted* / hasRole *会返回true，否则返回false表示授权失败



ModularRealmAuthorizer 进行多 Realm 匹配流程

1. 首先检查相应的Realm是否实现了Authorizer
2. 如果实现了Authorizer，那么接着调用其相应的isPermitted* / hasRole * 接口进行匹配
3. 如果有一个Realm 匹配，那么将返回true，否则返回 false



如果Realm 进行授权的话，应该继承AuthorizingRealm，其流程是

1. 如果调用hasRole*，则直接回去AuthorizationInfo.getRoles() 与传入的角色进行比较即可，
2. 首先如果调用如 isPermitted("user:view") ，首先通过 PermissionResolver 将权限字符串转换成相应的 Permission 实例，默认使用 WildcardPermissionResolver，即转换为通配符的 WildcardPermission
3. 通过 AuthorizationInfo.getObjectPermission() 得到 Permission 实例集合，通过AuthorizationInfo.getStringPermission() 得到字符串集合并通过 PermissionResolver 解析为Permission实例，然后获取用户的角色，并通过你RolePermissionResolver解析角色对应的权限集合（默认没有实现，可以自己提供）
4. 接着调用 Permission.implies(Permission p) 逐个与传入的权限比较，如果有匹配的则返回true 否则返回false

## Realm

### IniRealm

#### IniRealmDemo

```java
//实例化一个IniRealm对象，参数为配置文件的资源路径
IniRealm iniRealm = new IniRealm("classpath:shiro.ini");

//构建 SecurityManager 环境，
DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();

//添加 Realm 以作验证
defaultSecurityManager.setRealm(iniRealm);

//在运行环境中通过 SecurityUtils.setSecurityManager() 对象
SecurityUtils.setSecurityManager(defaultSecurityManager);

//通过 SecurityUtils.getSubject() 获取 Subject 对象
Subject subject = SecurityUtils.getSubject();

//实例化 UsernamePasswordToken 对象，以便传递登录名/凭证
UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("admin","123123");

//调用 Subject.login() 方法认证用户 =》 登录
subject.login(usernamePasswordToken);

//通过 Subject.isAuthenticated() 判断用户是否已经认证
if(subject.isAuthenticated()){
    System.out.println("用户登录成功");
}
```

```ini
[users]
admin=123123
```

### JdbcRealmDemo

```java
//创建 JdbcRealm 数据源 =》 dataSource
DruidDataSource dataSource = new DruidDataSource();

{
    dataSource.setUrl("jdbc:mysql://localhost:3306/shirodemodb?useUnicode=true&amp;characterEncoding=UTF-8");
    dataSource.setUsername("root");
    dataSource.setPassword("xuzhi7162");
}

@Test
public void jdbcRealmTest(){

    //创建JdbcRealm实例
    JdbcRealm jdbcRealm = new JdbcRealm();

    //JdbcRealm 中查询用户权限锁
    // 当参数值为false，则不能从相应的表中查询用户的权限信息,只有当参数值为true时才能查询用户权				限信息，默认为false
    jdbcRealm.setPermissionsLookupEnabled(true);

    //默认只能查users表中的username和passward
    //根据自定义的表来指定sql进而查询用户信息
    String sql = "select password from users where username = ?";
    jdbcRealm.setAuthenticationQuery(sql);

    //根据自定义的表来指定sql进而查询相应用户的权限信息
    String sql2 = "select user_role from user_role_table where username = ?";
    jdbcRealm.setPermissionsQuery(sql2);

    //设置 JdbcRealm 的数据源
    jdbcRealm.setDataSource( dataSource );

    //构建 SecurityManager 环境，
    DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();

    //添加 Realm 以作验证
    defaultSecurityManager.setRealm(jdbcRealm);

    //在运行环境中通过 SecurityUtils.setSecurityManager() 对象
    SecurityUtils.setSecurityManager(defaultSecurityManager);

    //通过 SecurityUtils.getSubject() 获取 Subject 对象
    Subject subject = SecurityUtils.getSubject();

    //实例化 UsernamePasswordToken 对象，以便传递登录名/凭证
    UsernamePasswordToken usernamePasswordToken = new 	             														UsernamePasswordToken("xuzhi","123123");

    //调用 Subject.login() 方法认证用户 =》 登录
    subject.login(usernamePasswordToken);

    //通过 Subject.isAuthenticated() 判断用户是否已经认证
    if(subject.isAuthenticated()){
        System.out.println("用户登录成功");
    }
    if(subject.hasRole("admin")){
        System.out.println("该用户拥有该权限");
    }
}
```



### CustomRealm

#### CustomRealm

```java
package pro.zyyz.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomRealm extends AuthorizingRealm {

    //模拟数据库，并初始化数据 =》 用户表
    private Map<String , String> users = new HashMap<>();
    {
        users.put("xuzhi","123");
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        String username = (String)authenticationToken.getPrincipal();

        String password = queryPasswordByUsername( username );

        if(password == null){
            return null;
        }

        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username, password, "CustomRealm");

        return authenticationInfo;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        String username = (String)principalCollection.getPrimaryPrincipal();

        //获得用户角色信息
        Set<String> userRoles = queryRolesByUsername( username );

        //获得用户权限信息
        Set<String> userPermissions = queryPermissionByUsername( username );

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();

        simpleAuthorizationInfo.addRoles( userRoles );

        simpleAuthorizationInfo.addStringPermissions( userPermissions );

        return simpleAuthorizationInfo;
    }

    //模拟数据库查询用户权限表
    private Set<String> queryPermissionByUsername(String username) {
        Set<String> userPermissions = new HashSet<>();
        userPermissions.add("user:delete");
        userPermissions.add("user:update");
        return userPermissions;
    }

    //模拟数据库查询用户角色表
    private Set<String> queryRolesByUsername(String username) {
        Set<String> userRoles = new HashSet<>();
        userRoles.add("admin");
        userRoles.add("user");
        return userRoles;
    }

    //模拟数据库查询操作
    private String queryPasswordByUsername(String username){
        String password = users.get( username );
        return password;
    }
}

```

#### CustomRealmDemo

```java
@Test
public void customRealmTest(){
    CustomRealm customRealm = new CustomRealm();

    DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();

    defaultSecurityManager.setRealm(customRealm);

    SecurityUtils.setSecurityManager( defaultSecurityManager );

    Subject subject = SecurityUtils.getSubject();

    UsernamePasswordToken token = new UsernamePasswordToken("xuzhi", "123");

    subject.login( token );

    if(subject.isAuthenticated()){
        System.out.println("用户登录成功");
    }

    //测试用户是否具有 admin 角色信息
    if(subject.hasRole("admin")){
        System.out.println("该用户拥有该角色");
    }

    //测试用户是否有 user:delete 权限，如果没有则抛出异常
    subject.checkPermission("user:delete");
}
```

## Shiro加密

### MD5加密并设置盐值

```java
package pro.zyyz.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.Md5Hash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CustomRealm extends AuthorizingRealm {

    //模拟数据库，并初始化数据 =》 用户表
    private Map<String , String> users = new HashMap<>();
    {
        //设置的用户密码为进行md5加密并增加盐值之后的密码
        users.put("xuzhi","753b4e3ac73d7217e1d31ed6bb1a36aa");
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {

        String username = (String)authenticationToken.getPrincipal();

        String password = queryPasswordByUsername( username );

        if(password == null){
            return null;
        }

        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo( username, password, "CustomRealm");

        //设置盐值
        authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes("xuzhi"));

        return authenticationInfo;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        String username = (String)principalCollection.getPrimaryPrincipal();

        //获得用户角色信息
        Set<String> userRoles = queryRolesByUsername( username );

        //获得用户权限信息
        Set<String> userPermissions = queryPermissionByUsername( username );

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();

        simpleAuthorizationInfo.addRoles( userRoles );

        simpleAuthorizationInfo.addStringPermissions( userPermissions );

        return simpleAuthorizationInfo;
    }

    //模拟数据库查询用户权限表
    private Set<String> queryPermissionByUsername(String username) {
        Set<String> userPermissions = new HashSet<>();
        userPermissions.add("user:delete");
        userPermissions.add("user:update");
        return userPermissions;
    }

    //模拟数据库查询用户角色表
    private Set<String> queryRolesByUsername(String username) {
        Set<String> userRoles = new HashSet<>();
        userRoles.add("admin");
        userRoles.add("user");
        return userRoles;
    }

    //模拟数据库查询操作
    private String queryPasswordByUsername(String username){
        String password = users.get( username );
        return password;
    }


    public static void main(String[] args){
        Md5Hash md5Hash = new Md5Hash("123","xuzhi");
        System.out.println(md5Hash.toString());
    }
}

```

```java
package pro.zyyz.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.subject.Subject;
import org.junit.Test;
import pro.zyyz.realm.CustomRealm;

public class CustomRealmDemo {

    @Test
    public void customRealmTest(){
        CustomRealm customRealm = new CustomRealm();

        //设置 md5 加密，加密次数为 1
        HashedCredentialsMatcher matcher = new HashedCredentialsMatcher();
        matcher.setHashAlgorithmName("md5");
        matcher.setHashIterations(1);
        customRealm.setCredentialsMatcher(matcher);

        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();

        defaultSecurityManager.setRealm(customRealm);

        SecurityUtils.setSecurityManager( defaultSecurityManager );

        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("xuzhi", "123");

        subject.login( token );

        if(subject.isAuthenticated()){
            System.out.println("用户登录成功");
        }

        //测试用户是否具有 admin 角色信息
        if(subject.hasRole("admin")){
            System.out.println("该用户拥有该角色");
        }

        //测试用户是否有 user:delete 权限，如果没有则抛出异常
        subject.checkPermission("user:delete");
    }
}

```









































