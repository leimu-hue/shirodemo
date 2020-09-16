package com.mvc;

import com.service.Service1;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpSession;


@Controller
public class MvcConfig {

    Logger logger = LoggerFactory.getLogger(MvcConfig.class);

    @Autowired
    private Service1 service;


    @GetMapping("/test")
    public String testShiroAnnotation(HttpSession httpSession){
        httpSession.setAttribute("test","测试shiro的session是否可以使用web的session");
        service.testPermission();
        return "testAnnotation";
    }

    @PostMapping(value = "/login")
    public String login(@RequestParam("username")String username,@RequestParam("password") String password){
        Subject subject = SecurityUtils.getSubject();

        if(!subject.isAuthenticated()){
            UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(username,password);
            usernamePasswordToken.setRememberMe(true);
            try{
                //传到realm的方法里面了
                subject.login(usernamePasswordToken);
            }catch (AuthenticationException ae){
                System.out.println(ae.getMessage());
                return "unauthorized";
            }
        }
        return "list";
    }
}
