package com.qcloud.cos.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.qcloud.cos.exception.CosClientException;
import com.qcloud.cos.internal.Constants;


public class HmacUtils {
    private static final String HMAC_SHA1 = "HmacSHA1";
    private static final Logger LOG = LoggerFactory.getLogger(HmacUtils.class);
    
    public static String hmacSha1Hex(String key, byte[] binaryDataToDigest) throws CosClientException {
        try {
            Mac mac = Mac.getInstance(HMAC_SHA1);
            SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1);
            mac.init(secretKey);
            byte[] HmacSha1Digest = mac.doFinal(binaryDataToDigest);
            return Hex.encodeHexString(HmacSha1Digest);
            
        } catch (NoSuchAlgorithmException e) {
            LOG.error("mac not find algorithm {}", HMAC_SHA1);
            throw new CosClientException(e.toString());
        } catch (InvalidKeyException e) {
            LOG.error("mac init key {} occur a error {}", key, e.toString());
            throw new CosClientException(e.toString());
        } catch (IllegalStateException e) {
            LOG.error("mac.doFinal occur a error {}", e.toString());
            throw e;
        }
    }
    
    public static String hmacSha1Hex(String key, String valultToDigest) throws CosClientException {
        try {
            return hmacSha1Hex(key, valultToDigest.getBytes(Constants.DEFAULT_ENCODING));
        } catch (UnsupportedEncodingException e) {
            LOG.error("unsupported encoding type exception {}", e.toString());
            throw new CosClientException(e.toString());
        }
    }
}
