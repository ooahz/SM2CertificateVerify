package com.sm2;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
* @author ahzoo
* @create 2021/11/30
* @desc
*/
public class AppTest {

    /**
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @desc 密钥对生成 + 签名 + 验签
     */
    @Test
    public void shouldAnswerWithTrue() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        // 获取SM2椭圆曲线的参数
        final ECGenParameterSpec sm2Spec = new ECGenParameterSpec("sm2p256v1");
        // 获取一个椭圆曲线类型的密钥对生成器
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 使用SM2参数初始化生成器
        kpg.initialize(sm2Spec);

        // 使用SM2的算法区域初始化密钥生成器
        kpg.initialize(sm2Spec, new SecureRandom());

        // 获取密钥对
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        System.out.println(Hex.toHexString(publicKey.toString().getBytes()));
        System.out.println(Hex.toHexString(privateKey.toString().getBytes()));

        System.out.println("公钥: " + Base64.toBase64String(publicKey.toString().getBytes()));
        System.out.println("私钥: " + Base64.toBase64String(privateKey.toString().getBytes()));

        // -----------签名----------------

        // 生成SM2sign with sm3 签名验签算法实例
        Signature signature = Signature.getInstance(
                GMObjectIdentifiers.sm2sign_with_sm3.toString()
                , new BouncyCastleProvider());

        // 签名需要使用私钥，使用私钥 初始化签名实例
        signature.initSign(privateKey);
        // 签名原文
        byte[] plainText = "ahzoo".getBytes(StandardCharsets.UTF_8);
        // 写入签名原文到算法中
        signature.update(plainText);
        // 计算签名值
        byte[] signatureValue = signature.sign();
        System.out.println("签名值：" + Base64.toBase64String(signatureValue));
        System.out.println(Hex.toHexString(signatureValue));

        // --------------验签--------------

        // 签名需要使用公钥，使用公钥 初始化签名实例
        signature.initVerify(publicKey);
        // 写入待验签的签名原文到算法中
        signature.update(plainText);
        // 验签
        System.out.println("签名验签结果: " + signature.verify(signatureValue));

    }


    /**
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @desc 证书验签
     */
    @Test
    public void CertificateVerify() throws NoSuchAlgorithmException, CertificateException, InvalidKeyException, SignatureException {
        // Base64编码的证书串，通常通过读取证书文件获取到，这里是一张SM2证书。
        String certStr = "MIIEgG2EBm.....+BRVyuCE9RpwjBg==";

        // Base64编码的签名原文
        String plaintext = "OTk5";

        // Base64编码的签名值（签名原文得到的签名值），此处的签名值实际上就是 R和S的sequence
        String signValueStr = "MEQCIB...v1WEhhOog==";

        byte[] signValue = Base64.decode(signValueStr);

        //解析证书

        CertificateFactory factory = new CertificateFactory();
        X509Certificate certificate = (X509Certificate) factory.engineGenerateCertificate(new ByteArrayInputStream(Base64.decode(certStr)));

        long l = System.currentTimeMillis();
        if (l < certificate.getNotBefore().getTime() || l > certificate.getNotAfter().getTime()) {
            System.out.println("证书有效期验证失败");
        }
        //System.out.println(certificate.getSigAlgName());

        // 验证签名
        Signature signature = Signature.getInstance(certificate.getSigAlgName(), new BouncyCastleProvider());
        signature.initVerify(certificate);
        signature.update(plaintext.getBytes(StandardCharsets.UTF_8));
        boolean verify = signature.verify(Base64.decode(signValueStr));
        System.out.println(verify);

    }
}
