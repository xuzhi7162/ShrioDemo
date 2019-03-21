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

        //设置加密类型，可选md5、sh1 等
        matcher.setHashAlgorithmName("md5");

        //设置加密次数
        matcher.setHashIterations(1);

        //将加密操作添加到相应的Realm中
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
