<?php

namespace App\Services;

use App\Services\Crypto\OpensslAES;
use Config;

class CryptoService extends Service
{

    public function __construct()
    {
        $this->privateKey = Config::get('APP_KEY');
    }

    public function encrypt($message)
    {
        $safe_data = OpensslAES::encrypt($message, $this->privateKey);

        return urlencode(base64_encode($safe_data));
    }

    public function decrypt($message)
    {
        $encrypted = base64_decode(urldecode($message));

        return OpensslAES::decrypt($encrypted, $this->privateKey);
    }
}
