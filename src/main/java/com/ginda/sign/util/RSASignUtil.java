package com.ginda.sign.util;

import com.ginda.sign.common.algorithm.RSA;

public class RSASignUtil {

    public static final String DEFAULT_CHARSET = "utf-8";

    /**
     * RSA签名(默认UTF8编码格式)
     *
     * @param content       待签名数据
     * @param privateKey    RSA私钥
     * @return 签名值
     */
    public static String sign(String content, String privateKey) throws Exception {
        return RSA.sign(content, privateKey, DEFAULT_CHARSET);
    }

    /**
     * RSA签名
     *
     * @param content       待签名数据
     * @param privateKey    RSA私钥
     * @param charset       编码格式
     * @return 签名值
     */
    public static String sign(String content, String privateKey, String charset) throws Exception {
        return RSA.sign(content, privateKey, charset);
    }

    /**
     * RSA验签名检查(默认UTF8编码格式)
     *
     * @param content        待签名数据
     * @param sign           签名值
     * @param publicKey      RSA公钥
     * @return 布尔值
     */
    public static boolean verify(String content, String sign, String publicKey) {
        return RSA.verify(content, sign, publicKey, DEFAULT_CHARSET);
    }

    /**
     * RSA验签名检查
     *
     * @param content        待签名数据
     * @param sign           签名值
     * @param publicKey      RSA公钥
     * @param charset  编码格式
     * @return 布尔值
     */
    public static boolean verify(String content, String sign, String publicKey, String charset) {
        return RSA.verify(content, sign, publicKey, charset);
    }
}
