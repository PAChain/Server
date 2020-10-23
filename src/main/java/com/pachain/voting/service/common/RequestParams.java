package com.pachain.voting.service.common;

import org.joda.time.DateTime;

import java.util.HashMap;

public class RequestParams extends HashMap<String,Object> {
    public String getString(String key){
        return getString(key,null);
    }
    public String getString(String key,String defaultValue){
        Object o = get(key);
        if(o!=null){
            return o.toString();
        }
        return defaultValue;
    }

    public int getInt(String key,int defaultValue){
        Object o = get(key);
        try {
            if (o != null) {
                return Integer.parseInt(o.toString());
            }
        }catch (Exception ex){}
        return defaultValue;
    }
    public Integer getInteger(String key){
        return getInteger(key,null);
    }
    public Integer getInteger(String key,Integer defaultValue){
        Object o = get(key);
        try {
            if (o != null) {
                return Integer.parseInt(o.toString());
            }
        }catch (Exception ex){}
        return defaultValue;
    }

    public boolean getBoolean(String key,boolean defaultValue){
        Object o = get(key);
        try {
            if (o != null) {
                return Boolean.parseBoolean(o.toString());
            }
        }catch (Exception ex){}
        return defaultValue;
    }
    public Boolean getBoolean(String key){
        return getBoolean(key,null);
    }
    public Boolean getBoolean(String key,Boolean defaultValue){
        Object o = get(key);
        try {
            if (o != null) {
                return Boolean.parseBoolean(o.toString());
            }
        }catch (Exception ex){}
        return defaultValue;
    }

    public DateTime getDateTime(String key){
        return getDateTime(key,null);
    }
    public DateTime getDateTime(String key,DateTime defaultValue){
        Object o = get(key);
        try {
            if (o != null) {
                return DateTime.parse(o.toString());
            }
        }catch (Exception ex){}
        return defaultValue;
    }
}
