package pro.zyyz.shiro;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.Realm;

import java.util.logging.Logger;

public class MyRealmDemo implements Realm {
    @Override
    public String getName() {
        return "myRealmDeml";
    }

    @Override
    public boolean supports(AuthenticationToken authenticationToken) {
        //判断authenticationToken是不是UsernamePasswordToken类型的
        return authenticationToken instanceof UsernamePasswordToken;
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //获得Token中的username 和 password
        String username = (String)authenticationToken.getPrincipal();
        String password = new String((char[])authenticationToken.getPrincipal());

        if(!"xuzhi".equals(username)){
            System.out.println("用户名不存在");
            throw new UnknownAccountException(); //如果username错误
        }
        if(!"123".equals(password)){
            System.out.println("密码错误");
            throw new IncorrectCredentialsException(); // 如果password错误
        }

        //如果身份认证成功
        return new SimpleAuthenticationInfo(username , password ,getName());
    }
}
