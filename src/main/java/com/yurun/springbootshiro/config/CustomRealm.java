package com.yurun.springbootshiro.config;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.swing.*;
import java.util.HashSet;
import java.util.Set;

/**
 * 描述：Realm：领域，主要是对用户进行身份的验证和权限的授予
 *
 * @author caojing
 * @create 2019-01-27-13:57
 */
public class CustomRealm extends AuthorizingRealm {
    /**
     * 用户的授权，
     * 查询用户的角色，查询用户权限，进行赋权
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("===========这块是在干啥=============");
        String username = (String) SecurityUtils.getSubject().getPrincipal();
        System.out.println("userName:"+username);
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        Set<String> stringSet = new HashSet<>();
        stringSet.add("user:show");
        stringSet.add("user:admin");
        stringSet.add("user:list");
        System.out.println("stringSet"+stringSet);
        info.setStringPermissions(stringSet);
        return info;
    }

    /**
     * 这里可以注入userService,为了方便演示，我就写死了帐号了密码
     *  UserService userService;
     * 获取即将需要认证的信息
     * 这块就是进行身份的认证，一般是查数据库，用户密码是否匹配
     *
     *
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("-------身份认证方法--------");
        //String userName = (String) authenticationToken.getPrincipal();
        //String userPwd = new String((char[]) authenticationToken.getCredentials());
        UsernamePasswordToken userToken = (UsernamePasswordToken) authenticationToken;
        String userName =userToken.getUsername();
        String userPwd=new String(userToken.getPassword());
        System.out.println(userName);
        System.out.println(userPwd);
        //根据用户名从数据库获取密码
        String password = "4b098730710898b2e2412482c855c5f7";
        if (userName == null) {
            throw new AccountException("用户名不正确");
        }
      //  return new SimpleAuthenticationInfo(userName+password, password,getName());
        return  new SimpleAuthenticationInfo(userName+password,password,ByteSource.Util.bytes(userName),getName());
    }











    /**
     * 重写方法,清除当前用户的的 授权缓存
     * @param principals
     */
    @Override
    public void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        super.clearCachedAuthorizationInfo(principals);
    }

    /**
     * 重写方法，清除当前用户的 认证缓存
     * @param principals
     */
    @Override
    public void clearCachedAuthenticationInfo(PrincipalCollection principals) {
        super.clearCachedAuthenticationInfo(principals);
    }

    @Override
    public void clearCache(PrincipalCollection principals) {
        super.clearCache(principals);
    }

    /**
     * 自定义方法：清除所有 授权缓存
     */
    public void clearAllCachedAuthorizationInfo() {
        getAuthorizationCache().clear();
    }

    /**
     * 自定义方法：清除所有 认证缓存
     */
    public void clearAllCachedAuthenticationInfo() {
        getAuthenticationCache().clear();
    }

    /**
     * 自定义方法：清除所有的  认证缓存  和 授权缓存
     */
    public void clearAllCache() {
        clearAllCachedAuthenticationInfo();
        clearAllCachedAuthorizationInfo();
    }









    public static void main(String[] args) {

        SimpleHash simpleHash = new SimpleHash("MD5", "123",  ByteSource.Util.bytes("user"),2);
        System.out.println(simpleHash.toHex());
        System.out.println(simpleHash.toBase64());
    }
}
