package com.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.util.ByteSource;

public class SecondRealm extends AuthenticatingRealm {
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("[SecondRealm]");
        //1、把参数进行转换,转换成为UsernamePasswordToken
        if(!(authenticationToken instanceof UsernamePasswordToken)){
            return null;
        }
        UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken)authenticationToken;
        //2、从UsernamePasswordToken中获得username
        String username = usernamePasswordToken.getUsername();
        //3、调用数据库方法，从数据库进行查询username对应的用户记录
        System.out.println("从数据库中获得username");
        //4、若用户不存在，就会抛出找不到用户的异常
        if("unknown".equals(username)){
            throw new UnknownAccountException("用户不存在");
        }
        //5、根据用户信息情况决定是否需要抛出其他异常
        if("monster".equals(username)){
            throw new LockedAccountException("用户被锁定");
        }
        //6、根据用户的情况，来构建AuthenticationInfo对象并且返回
        //以下信息从数据库获取
        //第一个参数：principal：认证的实体信息，也可以是数据表对应的实体类对象
        Object principal = username;
        //第二个参数：数据库获取的密码
        Object password = "123456";
        if("admin".equals(username)){
            password = "a3c5c0649b4a288bc30fd70b9939cfe28d2e89bb";
        }else if("user".equals(username)){
            password = "04769cff3fd75668b14db935a0db88d605e73bae";
        }
        //第三个参数是：当前realm对象的name
        String realmName = this.getName();
        //盐值,用唯一的字符串作为盐值
        ByteSource byteSource = ByteSource.Util.bytes(username);
        SimpleAuthenticationInfo info = null;//new SimpleAuthenticationInfo(principal,password,realmName);
        //这样就使用了盐值加密，防止MD5字符串一致
        info = new SimpleAuthenticationInfo(principal,password,byteSource,realmName);
        return info;
    }
    //最终使用SimpleHash来进行计算对应的密码值
}
