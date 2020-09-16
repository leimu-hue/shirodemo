package com.service;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

@Service
public class Service1 {

    @RequiresRoles(value = {"admin"})
    public void testPermission(){
        System.out.println("testPermission--->"+new Date().toString());

        Subject subject = SecurityUtils.getSubject();

        Session session = subject.getSession(false);

        if(session!=null){
            System.out.println("Service1-->"+session.getAttribute("test"));
        }

    }

}
