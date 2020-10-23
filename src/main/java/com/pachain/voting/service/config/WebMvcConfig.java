package com.pachain.voting.service.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.util.PathMatcher;
import org.springframework.web.accept.ContentNegotiationManager;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.PathMatchConfigurer;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurationSupport;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.servlet.resource.ResourceUrlProvider;
import org.springframework.web.util.UrlPathHelper;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

@Configuration("VotingWebMvcConfig")
public class WebMvcConfig extends WebMvcConfigurationSupport {

    @Override
    protected void addCorsMappings(CorsRegistry registry) {
        //super.addCorsMappings(registry);
        registry.addMapping("/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS")
                .allowCredentials(true)
                .maxAge(3600)
                .allowedHeaders("*");
    }

    @Override
    protected void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/templates/**").addResourceLocations("classpath:/templates/");
        registry.addResourceHandler("/**").addResourceLocations("classpath:/");
        super.addResourceHandlers(registry);
    }

    @Override
    protected void extendHandlerExceptionResolvers(List<HandlerExceptionResolver> exceptionResolvers) {
        exceptionResolvers.add(0,new ExceptionHandler());
       super.extendHandlerExceptionResolvers(exceptionResolvers);
    }

        @Override
    public RequestMappingHandlerMapping requestMappingHandlerMapping(ContentNegotiationManager contentNegotiationManager, FormattingConversionService conversionService, ResourceUrlProvider resourceUrlProvider) {
        //return super.requestMappingHandlerMapping(contentNegotiationManager, conversionService, resourceUrlProvider);
        RequestMappingHandler mapping = new RequestMappingHandler();
        mapping.setOrder(0);
        mapping.setInterceptors(this.getInterceptors(conversionService, resourceUrlProvider));
        mapping.setContentNegotiationManager(contentNegotiationManager);
        mapping.setCorsConfigurations(this.getCorsConfigurations());
        PathMatchConfigurer configurer = this.getPathMatchConfigurer();
        Boolean useSuffixPatternMatch = configurer.isUseSuffixPatternMatch();
        if (useSuffixPatternMatch != null) {
            mapping.setUseSuffixPatternMatch(useSuffixPatternMatch);
        }
        Boolean useRegisteredSuffixPatternMatch = configurer.isUseRegisteredSuffixPatternMatch();
        if (useRegisteredSuffixPatternMatch != null) {
            mapping.setUseRegisteredSuffixPatternMatch(useRegisteredSuffixPatternMatch);
        }
        Boolean useTrailingSlashMatch = configurer.isUseTrailingSlashMatch();
        if (useTrailingSlashMatch != null) {
            mapping.setUseTrailingSlashMatch(useTrailingSlashMatch);
        }
        UrlPathHelper pathHelper = configurer.getUrlPathHelper();
        if (pathHelper != null) {
            mapping.setUrlPathHelper(pathHelper);
        }

        PathMatcher pathMatcher = configurer.getPathMatcher();
        if (pathMatcher != null) {
            mapping.setPathMatcher(pathMatcher);
        }
        try {
            Method getPathPrefixes = configurer.getClass().getDeclaredMethod("getPathPrefixes", (Class[]) null);
            getPathPrefixes.setAccessible(true);
            Map<String, Predicate<Class<?>>> pathPrefixes = (Map<String, Predicate<Class<?>>>) getPathPrefixes.invoke(configurer, (Object[]) null);
            if (pathPrefixes != null) {
                mapping.setPathPrefixes(pathPrefixes);
            }
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return mapping;
    }

}
