package pro.zyyz.shiro;

import com.alibaba.druid.pool.DruidDataSource;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.jdbc.JdbcRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Test;

public class JdbcRealmDemo {

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
        // 当参数值为false，则不能从相应的表中查询用户的权限信息,只有当参数值为true时才能查询用户权限信息，默认为false
        jdbcRealm.setPermissionsLookupEnabled(true);

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
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("xuzhi","123123");

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

}
