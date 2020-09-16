package com.springconfig;

import com.mchange.v2.c3p0.ComboPooledDataSource;
import com.mchange.v2.util.PropertiesUtils;
import com.realm.AuthPower;
import com.realm.MyRealm;
import com.service.Service1;
import com.session.MySessionDAO;
import com.springconfig.bean.DataSourceMessage;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.pam.AllSuccessfulStrategy;
import org.apache.shiro.authc.pam.AuthenticationStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.session.mgt.eis.JavaUuidSessionIdGenerator;
import org.apache.shiro.session.mgt.eis.SessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

import java.beans.PropertyVetoException;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;

@Configuration
public class ShiroConfig {
    /**
     * 设置ShiroFilterFactoryBean,最终spring会通过id来找到被代理的filter，进行执行
     * @param securityManager
     * @return
     */
    @Bean(name = "shiro")
    public ShiroFilterFactoryBean shiro(SecurityManager securityManager){
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        shiroFilterFactoryBean.setLoginUrl("/login.jsp");
        shiroFilterFactoryBean.setSuccessUrl("/list.jsp");
        shiroFilterFactoryBean.setUnauthorizedUrl("/unauthorized.jsp");
        /**
         * 这里设置一些权限，但是请注意：可以不需要死写，而是通过数据库表来进行获取
         */
        HashMap<String,String> map = new HashMap<>();
        map.put("/*.jar","anon");
        map.put("/login","anon");
        map.put("/loginout","logout");
        map.put("/login.jsp","anon");
        map.put("/user.jsp","authc,roles[user]");
        map.put("/admin.jsp","authc,roles[admin]");
        map.put("/**","authc");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(map);

        return shiroFilterFactoryBean;
    }

    /**
     * 设置SecurityManager，并且添加多realms
     * @param cacheManager
     * @param modularRealmAuthenticator
     * @param jdbcRealm
     * @param secondRealm
     * @return
     */
    @Bean
    public SecurityManager securityManager(CacheManager cacheManager, ModularRealmAuthenticator modularRealmAuthenticator,Realm jdbcRealm,Realm secondRealm,SessionManager sessionManager){
        SecurityManager securityManager = new DefaultWebSecurityManager();
        ((DefaultWebSecurityManager) securityManager).setCacheManager(cacheManager);
        ((DefaultWebSecurityManager) securityManager).setAuthenticator(modularRealmAuthenticator);
        List<Realm> list = new ArrayList<>();
        list.add(jdbcRealm);
        list.add(secondRealm);
        //设置Realms
        ((DefaultWebSecurityManager) securityManager).setRealms(list);
        //设置session管理器
        ((DefaultWebSecurityManager) securityManager).setSessionManager(sessionManager);
        return securityManager;
    }

    /**
     * 添加缓存管理器
     * @return
     */
    @Bean
    public CacheManager cacheManager(){
        CacheManager cacheManager = new EhCacheManager();
        ((EhCacheManager) cacheManager).setCacheManagerConfigFile("classpath:cache/ehcache.xml");
        return cacheManager;
    }

    /**
     * 配置最终用于管理多Realm的一个权限验证管理器
     * @param authenticationStrategy
     * @return
     */
    @Bean
    public ModularRealmAuthenticator modularRealmAuthenticator(AuthenticationStrategy authenticationStrategy){
        ModularRealmAuthenticator modularRealmAuthenticator = new ModularRealmAuthenticator();
        modularRealmAuthenticator.setAuthenticationStrategy(authenticationStrategy);
        return modularRealmAuthenticator;
    }

    /**
     * 注入一个权限验证的策略，这一个表示必须全部的Realm都验证通过才可以通过
     *  这里一共有三种策略
     * @return
     */
    @Bean
    public AuthenticationStrategy authenticationStrategy(){
        return new AllSuccessfulStrategy();
    }

    //注入对应的Realm
    @Bean
    public Realm jdbcRealm(){
        MyRealm myRealm = new MyRealm();
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("MD5");
        hashedCredentialsMatcher.setHashIterations(5);
        myRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        return myRealm;
    }
    //这一个Realm可以为当前用户设置角色
    @Bean
    public Realm secondRealm(){
        AuthPower secondRealm = new AuthPower();
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        hashedCredentialsMatcher.setHashAlgorithmName("SHA1");
        hashedCredentialsMatcher.setHashIterations(5);
        secondRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        return secondRealm;
    }
    //生命周期处理器，会自动调用对应的init和destory方法
    //用于管理shiro的一些bean生命周期
    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){
        return new LifecycleBeanPostProcessor();
    }
    //配置这个可以用于扫描上下文，寻找所有的Advistor通知器，将这些Advisor应用到所有符合切入点
    //的Bean中，所以必须在上面的组件创建完成之后才会进行创建。所以需要使用@DependsOn
    @DependsOn(value = "lifecycleBeanPostProcessor")
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        return new DefaultAdvisorAutoProxyCreator();
    }
    //表示开启shiro的一些权限注解
    //如果没有这个，那么shiro的一些注解就无法生效
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * 加入一个service类，用于测试注解权限
     */
    @Bean
    public Service1 service(){
        return new Service1();
    }

    /**
     * 下面是配置Shiro的Session
     */
    //配置session ID生成器
    @Bean
    public SessionIdGenerator sessionIdGenerator(){
        return new JavaUuidSessionIdGenerator();
    }
    //配置Session DAO，操作Session里面的信息
    @Bean
    public SessionDAO sessionDAO(SessionIdGenerator sessionIdGenerator){
        String activeCacheName = "shiro-activeSessionCache";
        MySessionDAO mySessionDAO = new MySessionDAO(activeCacheName,sessionIdGenerator);
        return mySessionDAO;
    }
    //配置会话管理器
    @Bean
    public SessionManager sessionManager(SessionDAO sessionDAO){
        SessionManager sessionManager = new DefaultWebSessionManager();
        ((DefaultSessionManager) sessionManager).setGlobalSessionTimeout(1800000);
        ((DefaultSessionManager) sessionManager).setDeleteInvalidSessions(true);
        ((DefaultSessionManager) sessionManager).setSessionValidationSchedulerEnabled(true);
        ((DefaultSessionManager) sessionManager).setSessionDAO(sessionDAO);
        //设置session，防止出现jsessionid在导航栏的情况
        ((DefaultWebSessionManager) sessionManager).setSessionIdUrlRewritingEnabled(false);
        return sessionManager;
    }

    Properties properties = new Properties();
    @Bean
    public DataSourceMessage dataSourceMessage(){
        InputStream inputStream = null;
        //使用ClassLoader来进行加载properties
        inputStream = PropertiesUtils.class.getClassLoader().getResourceAsStream("data/datasource.properties");

        try {
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        DataSourceMessage dataSourceMessage = new DataSourceMessage();
        dataSourceMessage.setDriver(properties.getProperty("driver"));
        dataSourceMessage.setUser(properties.getProperty("username"));
        dataSourceMessage.setPassword(properties.getProperty("password"));
        dataSourceMessage.setJdbcUrl(properties.getProperty("url"));
        return dataSourceMessage;
    }

    /**
     * 下面配置数据源和JdbcTemplate
     */
    @Bean
    public ComboPooledDataSource comboPooledDataSource(DataSourceMessage dataSourceMessage) throws PropertyVetoException {
        ComboPooledDataSource comboPooledDataSource = new ComboPooledDataSource();
        comboPooledDataSource.setPassword(dataSourceMessage.getPassword());
        comboPooledDataSource.setUser(dataSourceMessage.getUser());
        comboPooledDataSource.setJdbcUrl(dataSourceMessage.getJdbcUrl());
        comboPooledDataSource.setDriverClass(dataSourceMessage.getDriver());
        return comboPooledDataSource;
    }

    @Bean
    public JdbcTemplate jdbcTemplate(ComboPooledDataSource comboPooledDataSource){
        JdbcTemplate jdbcTemplate = new JdbcTemplate();
        jdbcTemplate.setDataSource(comboPooledDataSource);
        return jdbcTemplate;
    }

}
