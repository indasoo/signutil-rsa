package com.ginda.sign.common.algorithm;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA {

    public static final String KEY_ALGORITHMS = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";

    /**
     * RSA签名
     *
     * @param content       待签名数据
     * @param privateKey    RSA私钥
     * @param charset       编码格式
     * @return 签名值
     */
    public static String sign(String content, String privateKey, String charset) throws Exception {

        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
        PrivateKey priKey = KeyFactory.getInstance(KEY_ALGORITHMS).generatePrivate(priPKCS8);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(priKey);
        signature.update(content.getBytes(charset));

        return Base64.encode(signature.sign());
    }

    /**
     * RSA验签名检查
     *
     * @param content        待签名数据
     * @param sign           签名值
     * @param publicKey      RSA公钥
     * @param charset        编码格式
     * @return 布尔值
     */
    public static boolean verify(String content, String sign, String publicKey, String charset) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHMS);
            PublicKey pubKey = keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decode(publicKey)));

            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(pubKey);
            signature.update(content.getBytes(charset));

            return signature.verify(Base64.decode(sign));

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }
}