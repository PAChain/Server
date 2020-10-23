package com.pachain.voting.service.config;

import com.pachain.voting.service.common.GlobalUtils;
import com.pachain.voting.service.controller.API.BallotController;
import org.slf4j.Logger;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.util.Set;

public class RequestMappingHandler extends RequestMappingHandlerMapping {
    private static Logger logger = org.slf4j.LoggerFactory.getLogger(RequestMappingHandler.class);

    @Override
    protected HandlerMethod handleNoMatch(Set<RequestMappingInfo> infos, String lookupPath, HttpServletRequest request) throws ServletException {
        logger.error(request.getRemoteAddr()+" --> Request Not Match: "+lookupPath+"\r\nQuery String: "+request.getQueryString()+"\r\nForm Data: "+ GlobalUtils.getRequestFormData(request));
        try {
            return new HandlerMethod(GlobalUtils.GetBean("initController"), "RequestNoMatch",HttpServletRequest.class);
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        return super.handleNoMatch(infos, lookupPath, request);
    }
}
