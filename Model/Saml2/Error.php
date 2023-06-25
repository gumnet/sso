<?php

namespace GumNet\SSO\Model\Saml2;

/**
 * Error class of PHP Toolkit
 *
 * Defines the Error class
 */
class Error extends \Exception
{
    // Errors
    public const SETTINGS_FILE_NOT_FOUND = 0;
    public const SETTINGS_INVALID_SYNTAX = 1;
    public const SETTINGS_INVALID = 2;
    public const METADATA_SP_INVALID = 3;
    public const SP_CERTS_NOT_FOUND = 4;
    // SP_CERTS_NOT_FOUND is deprecated, use CERT_NOT_FOUND instead
    public const CERT_NOT_FOUND = 4;
    public const REDIRECT_INVALID_URL = 5;
    public const PUBLIC_CERT_FILE_NOT_FOUND = 6;
    public const PRIVATE_KEY_FILE_NOT_FOUND = 7;
    public const SAML_RESPONSE_NOT_FOUND = 8;
    public const SAML_LOGOUTMESSAGE_NOT_FOUND = 9;
    public const SAML_LOGOUTREQUEST_INVALID = 10;
    public const SAML_LOGOUTRESPONSE_INVALID  = 11;
    public const SAML_SINGLE_LOGOUT_NOT_SUPPORTED = 12;
    public const PRIVATE_KEY_NOT_FOUND = 13;
    public const UNSUPPORTED_SETTINGS_OBJECT = 14;

    /**
     * Constructor
     *
     * @param string     $msg  Describes the error.
     * @param int        $code The code error (defined in the error class).
     * @param array|null $args Arguments used in the message that describes the error.
     */
    public function __construct($msg, $code = 0, $args = null)
    {
        assert('is_string($msg)');
        assert('is_int($code)');

        $message = Utils::t($msg, $args);

        parent::__construct($message, $code);
    }
}

/**
 * This class implements another custom Exception handler,
 * related to exceptions that happens during validation process.
 */
