package com.qf.md5;

import org.apache.shiro.crypto.hash.Md5Hash;
import org.junit.Test;

public class Md5Demo {

    @Test
    public void test_md5() {
        //明文 原始密码
        String password = "123";
        //盐
        String salt = "abc";
        //散列
        int hashIterations = 2;

        Md5Hash md5Hash = new Md5Hash(password);
        System.out.println(md5Hash.toString());

        Md5Hash md5Hash1 = new Md5Hash(password,salt);
        System.out.println(md5Hash1.toString());

        Md5Hash md5Hash2 = new Md5Hash(password,salt,hashIterations);
        System.out.println(md5Hash2.toString());
    }
}

