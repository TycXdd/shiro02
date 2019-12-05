package com.qf.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.ArrayList;
import java.util.HashSet;

public class RealmDemo extends AuthorizingRealm {

    private String realmName = "RealmDemo";

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取登录的身份信息
        Object primaryPrincipal = principalCollection.getPrimaryPrincipal();
        System.out.println(primaryPrincipal);

        //去数据库进行查询

        //创建角色集合
        ArrayList<String> roles = new ArrayList<>();
        roles.add("role1");
        roles.add("role2");
        roles.add("role3");

        //创建资源集合
        HashSet<String> permission = new HashSet<>();
        permission.add("user:delete");
        permission.add("user:insert");

        //授权
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        //simpleAuthorizationInfo.addRoles(roles);
        simpleAuthorizationInfo.addStringPermissions(permission);

        return simpleAuthorizationInfo;

    }


    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        //从token中取出用户信息
        //用户名 身份信息、
        String principal = (String)authenticationToken.getPrincipal();

        System.out.println("用户名："+principal);

        Object credentials = authenticationToken.getCredentials();

        //类型转化
        String password = new String ((char[]) credentials);
        System.out.println("密码："+password);

        if ("jack".equals(principal) && "123".equals(password)) {
            SimpleAuthenticationInfo simpleAuthenticationInfo = new
                    SimpleAuthenticationInfo(principal, password,"RealmDemo");

            return simpleAuthenticationInfo;
        }

        throw new RuntimeException("用户名或密码错误");
    }
}
