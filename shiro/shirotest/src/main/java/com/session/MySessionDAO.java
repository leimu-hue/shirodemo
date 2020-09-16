package com.session;

import com.session.serilize.SerilizedUtils;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.ValidatingSession;
import org.apache.shiro.session.mgt.eis.EnterpriseCacheSessionDAO;
import org.apache.shiro.session.mgt.eis.SessionIdGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.io.Serializable;
import java.util.List;

public class MySessionDAO extends EnterpriseCacheSessionDAO {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * 配置sessionid生成器和sessioncache的名字
     * @param activeSessionCacheName
     * @param sessionIdGenerator
     */
    public MySessionDAO(String activeSessionCacheName,SessionIdGenerator sessionIdGenerator){
        super.setActiveSessionsCacheName(activeSessionCacheName);
        super.setSessionIdGenerator(sessionIdGenerator);
    }

    @Override
    protected Serializable doCreate(Session session) {
        //生成session的id
        Serializable serializable = generateSessionId(session);
        //进行赋值操作
        assignSessionId(session,serializable);
        String sql = "insert into sessions values(?,?)";
        jdbcTemplate.update(sql,serializable, SerilizedUtils.serialize(session));
        return session.getId();
    }

    @Override
    protected Session doReadSession(Serializable sessionId) {
        String sql = "select session from sessions where id=?";
        List<String> stringList = jdbcTemplate.queryForList(sql,String.class,sessionId);
        if(stringList.size()==0){
            return null;
        }
        return SerilizedUtils.deserialize(stringList.get(0));
    }

    @Override
    protected void doUpdate(Session session) {
        if(session instanceof ValidatingSession && !((ValidatingSession)session).isValid()){
            return;
        }
        String sql = "update sessions set session=? where id=?";
        jdbcTemplate.update(sql,SerilizedUtils.serialize(session),session.getId());
    }

    @Override
    protected void doDelete(Session session) {
        String sql = "delete * from sessions where id=?";
        jdbcTemplate.update(sql,session.getId());
    }
}
