package pro.zyyz.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;

public class IniRealmDemo {

    public static void main(String[] args){
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
    }
}
