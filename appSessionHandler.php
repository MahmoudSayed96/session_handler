<?php

/**
 * Custom session class handler
 * class functionality [start,kill,read,write]
 * 
 * start() => Start session
 * kill() => Session destroy
 * read() => Get session data based on session id
 * write() => Register data in session 
 */

// Determined the path for save session file
define('SESSION_SAVE_PATH', dirname(realpath(__FILE__)) . DIRECTORY_SEPARATOR . 'sessions');

class AppSessionHandler extends SessionHandler
{
    // cookies params
    private $sessionName = SESSION_NAME;
    private $sessionMaxLifetime = SESSION_LIFE_TIME;
    private $sessionSSL = false;
    private $sessionHttpOnly = true;
    private $sessionPath = '/';
    private $sessionDomin = SESSION_DOMIN;
    private $sessionSavePath = SESSION_SAVE_PATH;

    private $sessionTimeToLife = 30;

    // mcrypt data props
    private $sessionCipherAlgo = 'AES-128-ECB';
    private $sessionCipherMode = MCRYPT_MODE_ECB;
    private $sessionCipherKey = 'WYCRYPTK3Y@2019';


    // METHODS

    public function __construct()
    {
        $this->sessionSSL = isset($_SERVER['HTTPS']) ? true : false;
        $this->sessionDomain = str_replace('www.', '', $_SERVER['SERVER_NAME']);

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
    }

    public function __get($key)
    {
        if (isset($_SESSION[$key])) {
            $data = @unserialize($_SESSION[$key]);
            if ($data === false) {
                return $_SESSION[$key];
            } else {
                return $data;
            }
        } else {
            trigger_error('No session key ' . $key . ' exists', E_USER_NOTICE);
        }
    }

    public function __set($key, $value)
    {
        if (is_object($value)) {
            $_SESSION[$key] = serialize($value);
        } else {
            $_SESSION[$key] = $value;
        }
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
        $plain_text_data = openssl_decrypt(
            $cipher_data,
            $this->sessionCipherAlgo,
            $this->sessionCipherKey
        );
        return $plain_text_data;
    }

    public function write($session_id, $session_data)
    {
        $cipher_data = openssl_encrypt(
            $session_data,
            $this->sessionCipherAlgo,
            $this->sessionCipherKey
        );
        return parent::write($session_id, $cipher_data);
    }

    /****
     * start()
     * Start session and create one session file
     * Set session start time => setSessionStartTime();
     * Check session time to life was finished => checkSessionTimeValidation();
     * 
     *****/
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

    /*****
     * renewSession();
     * 
     * reset session start time
     * regenerate session id => session_regenerate_id(true);
     * * true - for delete old session id
     *****/
    private function renewSession()
    {
        $this->sessionStartTime = time(); // reset session start time
        return session_regenerate_id(true);
    }

    /*****
     * kill()
     * 
     *  Make $_SESSION empty =>session_unset();
     *  Delete cookie
     *  Destroy session
     *****/
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
