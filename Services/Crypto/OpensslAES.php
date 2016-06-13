<?php

namespace App\Services\Crypto;

class OpensslAES
{
    const METHOD = 'aes-256-cbc';

    public static function encrypt($message, $key)
    {
        list($encKey, $authKey) = self::splitKeys($key);

        $ivsize = openssl_cipher_iv_length(self::METHOD);
        $iv = openssl_random_pseudo_bytes($ivsize);

        $ciphertext = openssl_encrypt(
            $message,
            self::METHOD,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );

        $mac = hash_hmac('sha256', $iv.$ciphertext, $authKey, true);

        return $mac.$iv.$ciphertext;
    }

    public static function decrypt($message, $key)
    {
        list($encKey, $authKey) = self::splitKeys($key);

        $ivsize = openssl_cipher_iv_length(self::METHOD);
        $mac = mb_substr($message, 0, 32, '8bit');
        $iv = mb_substr($message, 32, $ivsize, '8bit');
        $ciphertext = mb_substr($message, 32 + $ivsize, null, '8bit');

        // Very important: Verify MAC before decrypting
        $calc = hash_hmac('sha256', $iv.$ciphertext, $authKey, true);

        if (!hash_equals($mac, $calc)) {
            throw new \Exception('MAC Validation failed');
        }

        return openssl_decrypt(
            $ciphertext,
            self::METHOD,
            $encKey,
            OPENSSL_RAW_DATA,
            $iv
        );
    }

    public static function splitKeys($masterKey)
    {
        // You probably want RFC 5869 HKDF here instead
        return [
            hash_hmac('sha256', 'encryption', $masterKey, true),
            hash_hmac('sha256', 'authentication', $masterKey, true)
        ];
    }
}
