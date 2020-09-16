package com.session.serilize;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.session.Session;

import java.io.*;
import java.nio.ByteOrder;

/**
 * Session进行序列化到
 */

public class SerilizedUtils {
    //进行序列化
    public static String serialize(Session session) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = null;
        try {
            objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            objectOutputStream.writeObject(session);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Base64.encodeToString(byteArrayOutputStream.toByteArray());
    }

    //进行反序列化
    public static Session deserialize(String sessionContent){
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.decode(sessionContent));
        ObjectInputStream objectInputStream = null;
        try {
            objectInputStream = new ObjectInputStream(byteArrayInputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
        Object o = null;
        try {
            o = objectInputStream.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

        return (Session)o;
    }

}
