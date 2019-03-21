package pro.zyyz.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class AuthenticationDemo {

    //测试用例，模拟安全数据，
    SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();
//    SimpleAccountRealm s1 = new SimpleAccountRealm();
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
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("xuzhi","123");

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
//        subject.checkRole("admmin1");
    }
}
