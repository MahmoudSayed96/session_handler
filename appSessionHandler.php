<?php

/**
 * Custom session class handler
 * class functionality [start,kill,read,write]
 */

// Determined the path for save session file
define('SESSION_SAVE_PATH', dirname(realpath(__FILE__)) . DIRECTORY_SEPARATOR . 'sessions');

class AppSessionHandler extends SessionHandler
{
    // cookies params
    private $sessionName = 'MYAPPESS';
    private $sessionMaxLifetime = 0;
    private $sessionSSL = false;
    private $sessionHttpOnly = true;
    private $sessionPath = '/';
    private $sessionDomin = '.phpdev.com';
    private $sessionSavePath = SESSION_SAVE_PATH;

    private $sessionTimeToLife = 30;

    // mcrypt data props
    private $sessionCipherAlgo = MCRYPT_BLOWFISH;
    private $sessionCipherMode = MCRYPT_MODE_ECB;
    private $sessionCipherKey = 'WYCRYPTK3Y@2019';

    // METHODS

    public function __construct()
    {
        // Session Runtime configuration

        // Override file php.ini
        ini_set('session.use_cookies', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.use_trans_sid', 0); // prevent hacking session id from URL
        ini_set('session.save_handler', 'files');

        session_name($this->sessionName);
        session_save_path($this->sessionSavePath);
        session_set_cookie_params(
            $this->sessionMaxLifetime,
            $this->sessionPath,
            $this->sessionDomin,
            $this->sessionSSL,
            $this->sessionHttpOnly
        );
        // For make this object control on SessionHandlerInterface
        session_set_save_handler(
            array($this, 'open'),
            array($this, 'close'),
            array($this, 'read'),
            array($this, 'write'),
            array($this, 'destroy'),
            array($this, 'gc')
        );
    }

    public function __get($key)
    {
        return (isset($_SESSION[$key])) ? $_SESSION[$key] : false;
    }

    public function __set($key, $value)
    {
        $_SESSION[$key] = $value;
    }

    public function __isset($key)
    {
        return isset($_SESSION[$key]) ? true : false;
    }

    public function read($session_id)
    {
        // get cipher data
        $cipher_data = parent::read($session_id);
        // convert cipher data to plain data
        $plain_text_data = mcrypt_decrypt(
            $this->sessionCipherAlgo,
            $this->sessionCipherKey,
            $cipher_data,
            $this->sessionCipherMode
        );
        return $plain_text_data;
    }

    public function write($session_id, $session_data)
    {
        $cipher_data = mcrypt_encrypt(
            $this->sessionCipherAlgo,
            $this->sessionCipherKey,
            $session_data,
            $this->sessionCipherMode
        );
        return parent::write($session_id, $cipher_data);
    }

    /**
     * start()
     * TODO: Start session and create one session file
     * TODO: Set session start time => setSessionStartTime();
     * TODO: Check session time to life was finished => checkSessionTimeValidation();
     * 
     */
    public function start()
    {
        // Checking session exists
        if (session_id() === "") {
            if (session_start()) {
                $this->setSessionStartTime();
                $this->checkSessionTimeValidation();
            }
        }
    }

    private function setSessionStartTime()
    {
        if (!isset($this->sessionStartTime)) {
            $this->sessionStartTime = time();
        }
        return true;
    }

    private function checkSessionTimeValidation()
    {
        if ((time() - $this->sessionStartTime) > ($this->sessionTimeToLife * 60)) {
            $this->renewSession();
            $this->generateFingerPrint();
        }
        return true;
    }

    /**
     * renewSession();
     * 
     * TODO: reset session start time
     * TODO: regenerate session id => session_regenerate_id(true);
     * * true - for delete old session id
     */
    private function renewSession()
    {
        $this->sessionStartTime = time(); // reset session start time
        return session_regenerate_id(true);
    }

    /**
     * kill()
     * 
     * TODO: Make $_SESSION empty =>session_unset();
     * TODO: Delete cookie
     * TODO: Destroy session
     */
    public function kill()
    {
        session_unset();
        // delete cookie
        setcookie(
            $this->sessionName,
            '',
            time() - 1000,
            $this->sessionPath,
            $this->sessionDomin,
            $this->sessionSSL,
            $this->sessionHttpOnly
        );
        session_destroy();
    }

    private function generateFingerPrint()
    {
        $userAgentId = $_SERVER['HTTP_USER_AGENT'];
        $sessionId = session_id();
        $this->cipherKey = mcrypt_create_iv(16);
        $this->fingerPrint = md5($userAgentId . $sessionId . $this->cipherKey);
    }

    // For protect session from hacking
    public function isValidFingerPrint()
    {
        if (!isset($this->fingerPrint)) {
            $this->generateFingerPrint();
        }
        // User request
        $fingerPrint = md5($_SERVER['HTTP_USER_AGENT'] . session_id() . $this->cipherKey);
        if ($fingerPrint === $this->fingerPrint) {
            return true;
        }
        return false;
    }
}
