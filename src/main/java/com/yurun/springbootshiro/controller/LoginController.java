package com.yurun.springbootshiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

/**
 * ClassName: LoginController
 * Description:
 * date: 2019/12/1 19:40
 *
 * @author gaoxi
 * @since JDK 1.8
 */
@Controller
public class LoginController {


    @GetMapping("login")
    public String doLogin(){
        return "login";
    }


    @PostMapping(value = "/login")
    public ModelAndView login( @RequestParam("username") String username, @RequestParam("password") String password) {

        ModelAndView modelAndView = new ModelAndView();

        // 从SecurityUtils里边创建一个 subject
        Subject subject = SecurityUtils.getSubject();
        // 在认证提交前准备 token（令牌）
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        //设置记住我
        token.setRememberMe(true);
        // 执行认证登陆
        try {
            if(!subject.isAuthenticated())
            {
                subject.login(token);
            }

        } catch (UnknownAccountException uae) {
            modelAndView.addObject("error","认证失败");
        } catch (IncorrectCredentialsException ice) {
            modelAndView.addObject("error","密码不正确");
        } catch (LockedAccountException lae) {
            modelAndView.addObject("error","账户已锁定");
        } catch (ExcessiveAttemptsException eae) {
            modelAndView.addObject("error","用户名或密码错误次数过多");
        } catch (AuthenticationException ae) {
            modelAndView.addObject("error","用户名或密码不正确！");

        }
        if (subject.isAuthenticated()) {
            modelAndView.setViewName("redirect:/success.html");
            return  modelAndView;
        } else {
            token.clear();
            modelAndView.setViewName("fail");
            return  modelAndView;
        }
    }





}
