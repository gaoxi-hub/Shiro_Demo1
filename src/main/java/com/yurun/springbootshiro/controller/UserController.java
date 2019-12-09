package com.yurun.springbootshiro.controller;

import com.yurun.springbootshiro.config.CustomRealm;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * ClassName: UserController
 * Description:
 * date: 2019/12/1 19:57
 *
 * @author gaoxi
 * @since JDK 1.8
 */
@RequestMapping("/user")
@Controller
public class UserController {
    @RequiresPermissions("user:list")
    @ResponseBody
    @RequestMapping("/show")
    public Object showUser() {

        Subject subject = SecurityUtils.getSubject();

        Object principal = subject.getPrincipal();

        System.out.println(principal);
        System.out.println(subject.isRemembered());
        System.out.println(subject.isAuthenticated());

        return principal;
    }



    @RequestMapping("clearAllCache")
    @ResponseBody
    public String clearAllCache(){
                //添加成功之后 清除缓存
                DefaultWebSecurityManager securityManager = (DefaultWebSecurityManager)SecurityUtils.getSecurityManager();
                CustomRealm shiroRealm = (CustomRealm) securityManager.getRealms().iterator().next();
                //清除权限 相关的缓存
                shiroRealm.clearAllCache();
                return "clearAll";
            }




}