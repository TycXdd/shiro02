package com.qf.authorization;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.junit.Test;
import org.springframework.http.converter.json.GsonHttpMessageConverter;

import java.util.Arrays;

public class AuthorizationDemo {
    // 用户登陆和退出
    @Test
    public void testAuthorization() {

        // 创建securityManager工厂，通过ini配置文件创建securityManager工厂
        Factory<SecurityManager> factory = new IniSecurityManagerFactory(
                "classpath:permission.ini");

        // 创建SecurityManager
        SecurityManager securityManager = factory.getInstance();

        // 将securityManager设置当前的运行环境中
        SecurityUtils.setSecurityManager(securityManager);

        // 从SecurityUtils里边创建一个subject
        Subject subject = SecurityUtils.getSubject();

        // 在认证提交前准备token（令牌）
        // 这里的账号和密码 将来是由用户输入进去
//        UsernamePasswordToken token = new UsernamePasswordToken("tom", "456");
        UsernamePasswordToken token = new UsernamePasswordToken("jack", "123");

        try {
            // 执行认证提交
            subject.login(token);
        } catch (AuthenticationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // 是否认证通过
        boolean isAuthenticated = subject.isAuthenticated();

        System.out.println("是否认证通过：" + isAuthenticated);
//
//        // 退出操作
//        subject.logout();
//
//        // 是否认证通过
//        isAuthenticated = subject.isAuthenticated();
//
//        System.out.println("是否认证通过：" + isAuthenticated);

        //认证通过权限进行判断（从数据库查看权限）

        //基于角色
        //判断单个角色
        boolean role1 = subject.hasRole("role1");
        System.out.println("单个角色:" + role1);

        //判断多个角色
        boolean allRoles = subject.hasAllRoles(Arrays.asList("role1", "role2"));
        System.out.println("多个角色:" + allRoles);

        //检查当前subject的角色
        //subject.checkRole("role3");//如果没有当前角色，会报异常

        System.out.println("-----------------------------------------");

        //基于资源
        //判断单个资源
        boolean permitted = subject.isPermitted("user:add");
        System.out.println(permitted);

        //基于资源
        //判断多个资源
        boolean permittedAll = subject.isPermittedAll("user:add","user:list");
        System.out.println(permittedAll);

        //检查资源
        //subject.checkPermission("user:update");

    }

    // 用户登陆和授权
    @Test
    public void testAuthorization_realm() {

        // 创建securityManager工厂，通过ini配置文件创建securityManager工厂
        Factory<SecurityManager> factory = new IniSecurityManagerFactory(
                "classpath:shiro-realm.ini");

        // 创建SecurityManager
        SecurityManager securityManager = factory.getInstance();

        // 将securityManager设置当前的运行环境中
        SecurityUtils.setSecurityManager(securityManager);

        // 从SecurityUtils里边创建一个subject
        Subject subject = SecurityUtils.getSubject();

        // 在认证提交前准备token（令牌）
        // 这里的账号和密码 将来是由用户输入进去
//        UsernamePasswordToken token = new UsernamePasswordToken("tom", "456");
        UsernamePasswordToken token = new UsernamePasswordToken("jack", "123");

        try {
            // 执行认证提交
            subject.login(token);
        } catch (AuthenticationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // 是否认证通过
        boolean isAuthenticated = subject.isAuthenticated();

        System.out.println("是否认证通过：" + isAuthenticated);
//
//        // 退出操作
//        subject.logout();
//
//        // 是否认证通过
//        isAuthenticated = subject.isAuthenticated();
//
//        System.out.println("是否认证通过：" + isAuthenticated);

        //认证通过权限进行判断（从数据库查看权限）

        //基于角色
        //判断单个角色


        boolean role1 = subject.hasRole("role1");
        System.out.println("单个角色:" + role1);

        //判断多个角色
        boolean allRoles = subject.hasAllRoles(Arrays.asList("role1", "role2"));
        System.out.println("多个角色:" + allRoles);

        //检查当前subject的角色
        //subject.checkRole("role3");//如果没有当前角色，会报异常

        System.out.println("-----------------------------------------");

        //基于资源
        //判断单个资源
        boolean permitted = subject.isPermitted("user:update");
        System.out.println(permitted);


        //基于资源
        //判断多个资源
        boolean permittedAll = subject.isPermittedAll("user:delete","user:insert");
        System.out.println(permittedAll);

        //检查资源
        //subject.checkPermission("user:update");

    }

}
