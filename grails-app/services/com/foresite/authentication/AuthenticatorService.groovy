package com.foresite.authentication

import grails.transaction.Transactional
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.apache.commons.codec.binary.Base32

// mostly copied from http://www.javacodegeeks.com/2011/12/google-authenticator-using-it-with-your.html

@Transactional
class AuthenticatorService {
    
    def generateKey() {
        // Allocating the buffer
      	byte[] buffer = new byte[10*8*5];
        println buffer.length
        new Random().nextBytes(buffer);

        // Getting the key and converting it to Base32
        Base32 codec = new Base32();
        
        byte[] secretKey = Arrays.copyOf(buffer, 10);
        
        byte[] bEncodedKey = codec.encode(secretKey);
        
        String encodedKey = new String(bEncodedKey);
        
        return encodedKey
        
    }

    def generateQRCodeURL (String user, String host, String secret, String issuer) {
        return String.format("otpauth://totp/%s:%s@%s?secret=%s&issuer=%s", issuer, user, host, secret, issuer)
    }
    
    boolean checkCode(String secret,long code, long t){
        Base32 codec = new Base32();
        byte[] decodedKey = codec.decode(secret);

        int window = 3;
        for (int i = -window; i <= window; ++i) {
            long hash = verifyCode(decodedKey, t + i);

            if (hash == code) {
                return true;
            }
        }

        return false;
    }

    def verifyCode(byte[] key, long t) {
        byte[] data = new byte[8];
        long value = t;
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }


        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        
        Mac mac = Mac.getInstance("HmacSHA1");
        
        mac.init(signKey);
        
        byte[] hash = mac.doFinal(data);


        int offset = hash[20 - 1] & 0xF;
  
        long truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= (hash[offset + i] & 0xFF);
        }


        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;


        return (int) truncatedHash;
    }

}
