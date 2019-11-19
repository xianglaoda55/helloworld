package com.how2java;

import java.util.ArrayList;
import java.util.List;
 
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;

public class TestShiro {

	public static void main(String[] args) {
		//用户们
        User zhang3 = new User();
        zhang3.setName("zhang3");
        zhang3.setPassword("12345");
 
        User li4 = new User();
        li4.setName("li4");
        li4.setPassword("abcde");
         
        User wang5 = new User();
        wang5.setName("wang5");
        wang5.setPassword("wrongpassword");
 
        List<User> users = new ArrayList<>();
         
        users.add(zhang3);
        users.add(li4);
        users.add(wang5);      
        //角色们
        String roleAdmin = "admin";
        String roleProductManager ="productManager";
         
        List<String> roles = new ArrayList<>();
        roles.add(roleAdmin);
        roles.add(roleProductManager);
         
        //权限们
        String permitAddProduct = "addProduct";
        String permitAddOrder = "addOrder";
         
        List<String> permits = new ArrayList<>();
        permits.add(permitAddProduct);
        permits.add(permitAddOrder);
         
        //登陆每个用户
        for (User user : users) {
            if(login(user))
                System.out.printf("%s \t成功登陆，用的密码是 %s\t %n",user.getName(),user.getPassword());
            else
                System.out.printf("%s \t成功失败，用的密码是 %s\t %n",user.getName(),user.getPassword());
        }
         
        System.out.println("-------how2j 分割线------");
         
        //判断能够登录的用户是否拥有某个角色
        for (User user : users) {
            for (String role : roles) {
                if(login(user)) {
                    if(hasRole(user, role))
                        System.out.printf("%s\t 拥有角色: %s\t%n",user.getName(),role);
                    else
                        System.out.printf("%s\t 不拥有角色: %s\t%n",user.getName(),role);
                }
            }  
        }
        System.out.println("-------how2j 分割线------");
 
        //判断能够登录的用户，是否拥有某种权限
        for (User user : users) {
            for (String permit : permits) {
                if(login(user)) {
                    if(isPermitted(user, permit))
                        System.out.printf("%s\t 拥有权限: %s\t%n",user.getName(),permit);
                    else
                        System.out.printf("%s\t 不拥有权限: %s\t%n",user.getName(),permit);
                }
            }  
        }
    }
     
    private static boolean hasRole(User user, String role) {
        Subject subject = getSubject(user);
        return subject.hasRole(role);
    }
     
    private static boolean isPermitted(User user, String permit) {
        Subject subject = getSubject(user);
        return subject.isPermitted(permit);
    }
 
    private static Subject getSubject(User user) {
        //加载配置文件，并获取工厂
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        //获取安全管理者实例
        SecurityManager sm = factory.getInstance();
        //将安全管理者放入全局对象
        SecurityUtils.setSecurityManager(sm);
        //全局对象通过安全管理者生成Subject对象
        Subject subject = SecurityUtils.getSubject();
 
        return subject;
    }
     
    private static boolean login(User user) {
        Subject subject= getSubject(user);
        //如果已经登录过了，退出
        if(subject.isAuthenticated())
            subject.logout();
         
        //封装用户的数据
        UsernamePasswordToken token = new UsernamePasswordToken(user.getName(), user.getPassword());
        try {
            //将用户的数据token 最终传递到Realm中进行对比
            subject.login(token);
        } catch (AuthenticationException e) {
            //验证错误
            return false;
        }              
         
        return subject.isAuthenticated();
	}
}
