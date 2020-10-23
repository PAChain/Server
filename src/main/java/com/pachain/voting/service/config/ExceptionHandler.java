package com.pachain.voting.service.config;

import com.alibaba.fastjson.JSONObject;
import com.pachain.voting.service.common.GlobalUtils;
import org.slf4j.Logger;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ExceptionHandler implements HandlerExceptionResolver {
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(RequestMappingHandler.class);
    @Override
    public ModelAndView resolveException(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Object o, Exception e) {
        logger.error(httpServletRequest.getRemoteAddr()+" -->Url: "+httpServletRequest.getRequestURI()+"\r\nQuery String: "+httpServletRequest.getQueryString()+"\r\nForm Data: "+ GlobalUtils.getRequestFormData(httpServletRequest)+"\r\nError: "+GlobalUtils.getException(e));
        ModelAndView modelAndView = new ModelAndView(new MappingJackson2JsonView());
        modelAndView.addObject("ret",false);
        modelAndView.addObject("error",e.getMessage());
        return modelAndView;
    }
}
