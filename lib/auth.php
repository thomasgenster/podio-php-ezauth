<?php

namespace PodioEzauth;
use Podio;

/**
 * Class PodioEzauth
 * @package PodioEzauth
 */
class PodioEzauth
{
    /**
     * @var string $uUrl
     * @var string $cId
     * @var string $cSecret
     * @var int $orgId
     * @var string $token
     */
    private static $rUrl, $cId, $cSecret, $orgId, $token = null;

    /**
     * @param string $redirectUrl
     * @param string $clientId
     * @param string $clientSecret
     * @param int $organizationId
     */
    public static function auth($redirectUrl, $clientId, $clientSecret, $organizationId)
    {
        session_start();
        self::$rUrl = $redirectUrl;
        self::$cId = $clientId;
        self::$cSecret = $clientSecret;
        self::$orgId = $organizationId;

        //Check for session first
        if(isset($_SESSION['podio_auth']) && $_SESSION['podio_auth'] === true) return;

        //Check for any error. If an error exist, die/exit
        if(isset($_REQUEST['error_reason']) && isset($_REQUEST['error']) && $_REQUEST['error'] === 'acccess_denied')
        {
            die('Access denied.');
        }

        Podio::setup(self::$cId, self::$cSecret);

        if(!Podio::is_authenticated())
        {
            if(!isset($_REQUEST['code']))
            {
                $_SESSION['return_url'] = self::$rUrl;
                header('location:' . Podio::authorize_url(self::$rUrl));
                die('Please wait for Podio.');
            }else
            {
                if(Podio::authenticate('authorization_code', array('code' => $_REQUEST['code'], 'redirect_uri' => $_SESSION['return_url'])))
                {
                    self::checkOrg();
                    $_SESSION['podio_auth'] = true;
                    header('location:' . $_SESSION['return_url']);
                }
            }
        }else
        {
            self::checkOrg();
            self::$token = Podio::$oauth->access_token;
        }
    }

    /**
     * @return null|string
     */
    public static function getToken()
    {
        return self::$token;
    }

    /**
     * @return void
     */
    public static function checkOrg()
    {
        try {
            if(!\PodioOrganization::get(172651)){
                die('Not member of org.');
            }
        }catch(\PodioForbiddenError $e)
        {
            die('Not member of org.');
        }
    }
}