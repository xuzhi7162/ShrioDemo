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

        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo( username, password, "CustomRealm");

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
