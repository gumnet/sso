<?php

namespace GumNet\SSO\Model\Saml2;

/**
 * Configuration of the PHP Toolkit
 *
 */

class Settings
{
    /**
     * List of paths.
     *
     * @var array
     */
    private array $paths = [];

    /**
     * @var string
     */
    private string $baseurl = "";

    /**
     * Strict. If active, PHP Toolkit will reject unsigned or unencrypted messages
     * if it expects them signed or encrypted. If not, the messages will be accepted
     * and some security issues will be also relaxed.
     *
     * @var bool
     */
    private bool $strict = true;

    /**
     * Activate debug mode
     *
     * @var bool
     */
    private bool $debug = false;

    /**
     * SP data.
     *
     * @var array
     */
    private array $sp = [];

    /**
     * IdP data.
     *
     * @var array
     */
    private array $idp = [];

    /**
     * Compression settings that determine
     * whether gzip compression should be used.
     *
     * @var array
     */
    private $compress = [];

    /**
     * Security Info related to the SP.
     *
     * @var array
     */
    private $security = [];

    /**
     * Setting contacts.
     *
     * @var array
     */
    private $contacts = [];

    /**
     * Setting organization.
     *
     * @var array
     */
    private $organization = [];

    /**
     * Setting errors.
     *
     * @var array
     */
    private $errors = [];

    /**
     * Setting errors.
     *
     * @var bool
     */
    private $spValidationOnly = false;

    /**
     * Initializes the settings:
     * - Sets the paths of the different folders
     * - Loads settings info from settings file or array/object provided
     *
     * @param array|object|null $settings SAML Toolkit Settings
     * @param bool $spValidationOnly
     *
     * @throws Error If any settings parameter is invalid
     * @throws Exception If Settings is incorrectly supplied
     */
    public function __construct(
        private readonly Utils $utils
    ) {
    }

    /**
     * Sets the paths of the different folders
     * @suppress PhanUndeclaredConstant
     */
    private function loadPaths()
    {
        $basePath = dirname(dirname(__DIR__)).'/';
        $this->paths = [
            'base' => $basePath,
            'config' => $basePath,
            'cert' => $basePath.'certs/',
            'lib' => __DIR__ . '/',
            'extlib' => $basePath.'extlib/'
        ];

        if (defined('ONELOGIN_CUSTOMPATH')) {
            $this->paths['config'] = ONELOGIN_CUSTOMPATH;
            $this->paths['cert'] = ONELOGIN_CUSTOMPATH.'certs/';
        }
    }

    /**
     * Returns base path.
     *
     * @return string  The base toolkit folder path
     */
    public function getBasePath(): string
    {
        return $this->paths['base'];
    }

    /**
     * Returns cert path.
     *
     * @return string The cert folder path
     */
    public function getCertPath(): string
    {
        return $this->paths['cert'];
    }

    /**
     * Returns config path.
     *
     * @return string The config folder path
     */
    public function getConfigPath(): string
    {
        return $this->paths['config'];
    }

    /**
     * Returns lib path.
     *
     * @return string The library folder path
     */
    public function getLibPath(): string
    {
        return $this->paths['lib'];
    }

    /**
     * Returns external lib path.
     *
     * @return string  The external library folder path
     */
    public function getExtLibPath(): string
    {
        return $this->paths['extlib'];
    }

    /**
     * Returns schema path.
     *
     * @return string  The external library folder path
     */
    public function getSchemasPath(): string
    {
        if (isset($this->paths['schemas'])) {
            return $this->paths['schemas'];
        }
        return __DIR__ . '/schemas/';
    }

    /**
     * Set schemas path
     *
     * @param string $path
     * @return Settings
     */
    public function setSchemasPath($path): Settings
    {
        $this->paths['schemas'] = $path;
        return $this;
    }

    /**
     * Loads settings info from a settings Array
     *
     * @param array $settingsArray SAML Toolkit Settings
     *
     * @return bool True if the settings info is valid
     */
    public function loadSettingsFromArray($settingsArray = []): bool
    {
        $settings = [
            'sp' => [
                'entityId' => 'https://<your_domain>'.'/demo1/metadata.php',
                'assertionConsumerService' => [
                    'url' => 'https://<your_domain>'.'/demo1/index.php?acs',
                ],
                'singleLogoutService' => [
                    'url' => 'https://<your_domain>'.'/demo1/index.php?sls',
                ],
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            ],
            'idp' => [
                'entityId' => '',
                'singleSignOnService' => [
                    'url' => '',
                ],
                'singleLogoutService' => [
                    'url' => '',
                ],
                'x509cert' => '',
            ],
        ];
        if (count($settingsArray)) {
            $settings = $settingsArray;
        }

        if (isset($settings['sp'])) {
            $this->sp = $settings['sp'];
        }
        if (isset($settings['idp'])) {
            $this->idp = $settings['idp'];
        }

        $errors = $this->checkSettings($settings);
        if (empty($errors)) {
            $this->errors = [];

            if (isset($settings['strict'])) {
                $this->strict = $settings['strict'];
            }
            if (isset($settings['debug'])) {
                $this->debug = $settings['debug'];
            }

            if (isset($settings['baseurl'])) {
                $this->baseurl = $settings['baseurl'];
            }

            if (isset($settings['compress'])) {
                $this->compress = $settings['compress'];
            }

            if (isset($settings['security'])) {
                $this->security = $settings['security'];
            }

            if (isset($settings['contactPerson'])) {
                $this->contacts = $settings['contactPerson'];
            }

            if (isset($settings['organization'])) {
                $this->organization = $settings['organization'];
            }

            $this->addDefaultValues();
            $this->formatIdPCert();
            $this->formatSPCert();
            $this->formatSPKey();
            $this->formatSPCertNew();
            $this->formatIdPCertMulti();
            return true;
        } else {
            $this->errors = $errors;
            return false;
        }
    }

    /**
     * Add default values if the settings info is not complete
     */
    private function addDefaultValues()
    {
        if (!isset($this->sp['assertionConsumerService']['binding'])) {
            $this->sp['assertionConsumerService']['binding'] = Constants::BINDING_HTTP_POST;
        }
        if (isset($this->sp['singleLogoutService']) && !isset($this->sp['singleLogoutService']['binding'])) {
            $this->sp['singleLogoutService']['binding'] = Constants::BINDING_HTTP_REDIRECT;
        }

        if (!isset($this->compress['requests'])) {
            $this->compress['requests'] = true;
        }

        if (!isset($this->compress['responses'])) {
            $this->compress['responses'] = true;
        }

        // Related to nameID
        if (!isset($this->sp['NameIDFormat'])) {
            $this->sp['NameIDFormat'] = Constants::NAMEID_UNSPECIFIED;
        }
        if (!isset($this->security['nameIdEncrypted'])) {
            $this->security['nameIdEncrypted'] = false;
        }
        if (!isset($this->security['requestedAuthnContext'])) {
            $this->security['requestedAuthnContext'] = true;
        }

        // sign provided
        if (!isset($this->security['authnRequestsSigned'])) {
            $this->security['authnRequestsSigned'] = false;
        }
        if (!isset($this->security['logoutRequestSigned'])) {
            $this->security['logoutRequestSigned'] = false;
        }
        if (!isset($this->security['logoutResponseSigned'])) {
            $this->security['logoutResponseSigned'] = false;
        }
        if (!isset($this->security['signMetadata'])) {
            $this->security['signMetadata'] = false;
        }

        // sign expected
        if (!isset($this->security['wantMessagesSigned'])) {
            $this->security['wantMessagesSigned'] = false;
        }
        if (!isset($this->security['wantAssertionsSigned'])) {
            $this->security['wantAssertionsSigned'] = false;
        }

        // NameID element expected
        if (!isset($this->security['wantNameId'])) {
            $this->security['wantNameId'] = true;
        }

        // Relax Destination validation
        if (!isset($this->security['relaxDestinationValidation'])) {
            $this->security['relaxDestinationValidation'] = false;
        }

        // Allow duplicated Attribute Names
        if (!isset($this->security['allowRepeatAttributeName'])) {
            $this->security['allowRepeatAttributeName'] = false;
        }

        // Strict Destination match validation
        if (!isset($this->security['destinationStrictlyMatches'])) {
            $this->security['destinationStrictlyMatches'] = false;
        }

        // InResponseTo
        if (!isset($this->security['rejectUnsolicitedResponsesWithInResponseTo'])) {
            $this->security['rejectUnsolicitedResponsesWithInResponseTo'] = false;
        }

        // encrypt expected
        if (!isset($this->security['wantAssertionsEncrypted'])) {
            $this->security['wantAssertionsEncrypted'] = false;
        }
        if (!isset($this->security['wantNameIdEncrypted'])) {
            $this->security['wantNameIdEncrypted'] = false;
        }

        // XML validation
        if (!isset($this->security['wantXMLValidation'])) {
            $this->security['wantXMLValidation'] = true;
        }

        // SignatureAlgorithm
        if (!isset($this->security['signatureAlgorithm'])) {
            $this->security['signatureAlgorithm'] = XMLSec\XMLSecurityKey::RSA_SHA1;
        }

        // DigestAlgorithm
        if (!isset($this->security['digestAlgorithm'])) {
            $this->security['digestAlgorithm'] = XMLSec\XMLSecurityDSig::SHA1;
        }

        if (!isset($this->security['lowercaseUrlencoding'])) {
            $this->security['lowercaseUrlencoding'] = false;
        }

        // Certificates / Private key /Fingerprint
        if (!isset($this->idp['x509cert'])) {
            $this->idp['x509cert'] = '';
        }
        if (!isset($this->idp['certFingerprint'])) {
            $this->idp['certFingerprint'] = '';
        }
        if (!isset($this->idp['certFingerprintAlgorithm'])) {
            $this->idp['certFingerprintAlgorithm'] = 'sha1';
        }

        if (!isset($this->sp['x509cert'])) {
            $this->sp['x509cert'] = '';
        }
        if (!isset($this->sp['privateKey'])) {
            $this->sp['privateKey'] = '';
        }
    }

    /**
     * Checks the settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the settings data
     */
    public function checkSettings($settings)
    {
        if (!is_array($settings) || empty($settings)) {
            $errors = ['invalid_syntax'];
        } else {
            $errors = [];
            if (!$this->spValidationOnly) {
                $idpErrors = $this->checkIdPSettings($settings);
                $errors = array_merge($idpErrors, $errors);
            }
            $spErrors = $this->checkSPSettings($settings);
            $errors = array_merge($spErrors, $errors);

            $compressErrors = $this->checkCompressionSettings($settings);
            $errors = array_merge($compressErrors, $errors);
        }

        return $errors;
    }

    /**
     * Checks the compression settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the settings data
     */
    public function checkCompressionSettings($settings)
    {
        $errors = [];

        if (isset($settings['compress'])) {
            if (!is_array($settings['compress'])) {
                $errors[] = "invalid_syntax";
            } else if (isset($settings['compress']['requests'])
                && $settings['compress']['requests'] !== true
                && $settings['compress']['requests'] !== false
            ) {
                $errors[] = "'compress'=>'requests' values must be true or false.";
            } else if (isset($settings['compress']['responses'])
                && $settings['compress']['responses'] !== true
                && $settings['compress']['responses'] !== false
            ) {
                $errors[] = "'compress'=>'responses' values must be true or false.";
            }
        }
        return $errors;
    }

    /**
     * Checks the IdP settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the IdP settings data
     */
    public function checkIdPSettings($settings)
    {
        if (!is_array($settings) || empty($settings)) {
            return ['invalid_syntax'];
        }

        $errors = [];

        if (!isset($settings['idp']) || empty($settings['idp'])) {
            $errors[] = 'idp_not_found';
        } else {
            $idp = $settings['idp'];
            if (!isset($idp['entityId']) || empty($idp['entityId'])) {
                $errors[] = 'idp_entityId_not_found';
            }

            if (!isset($idp['singleSignOnService'])
                || !isset($idp['singleSignOnService']['url'])
                || empty($idp['singleSignOnService']['url'])
            ) {
                $errors[] = 'idp_sso_not_found';
            } else if (!filter_var($idp['singleSignOnService']['url'], FILTER_VALIDATE_URL)) {
                $errors[] = 'idp_sso_url_invalid';
            }

            if (isset($idp['singleLogoutService'])
                && isset($idp['singleLogoutService']['url'])
                && !empty($idp['singleLogoutService']['url'])
                && !filter_var($idp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
            ) {
                $errors[] = 'idp_slo_url_invalid';
            }

            if (isset($idp['singleLogoutService'])
                && isset($idp['singleLogoutService']['responseUrl'])
                && !empty($idp['singleLogoutService']['responseUrl'])
                && !filter_var($idp['singleLogoutService']['responseUrl'], FILTER_VALIDATE_URL)
            ) {
                $errors[] = 'idp_slo_response_url_invalid';
            }

            $existsX509 = isset($idp['x509cert']) && !empty($idp['x509cert']);
            $existsMultiX509Sign = isset($idp['x509certMulti']) && isset($idp['x509certMulti']['signing']) && !empty($idp['x509certMulti']['signing']);
            $existsFingerprint = isset($idp['certFingerprint']) && !empty($idp['certFingerprint']);

            if (!($existsX509 || $existsFingerprint || $existsMultiX509Sign)
            ) {
                $errors[] = 'idp_cert_or_fingerprint_not_found_and_required';
            }

            if (isset($settings['security'])) {
                $existsMultiX509Enc = isset($idp['x509certMulti']) && isset($idp['x509certMulti']['encryption']) && !empty($idp['x509certMulti']['encryption']);

                if ((isset($settings['security']['nameIdEncrypted']) && $settings['security']['nameIdEncrypted'] == true)
                    && !($existsX509 || $existsMultiX509Enc)
                ) {
                    $errors[] = 'idp_cert_not_found_and_required';
                }
            }
        }

        return $errors;
    }

    /**
     * Checks the SP settings info.
     *
     * @param array $settings Array with settings data
     *
     * @return array $errors  Errors found on the SP settings data
     */
    public function checkSPSettings($settings)
    {
        if (!is_array($settings) || empty($settings)) {
            return ['invalid_syntax'];
        }

        $errors = [];

        if (!isset($settings['sp']) || empty($settings['sp'])) {
            $errors[] = 'sp_not_found';
        } else {
            $sp = $settings['sp'];
            $security = [];
            if (isset($settings['security'])) {
                $security = $settings['security'];
            }

            if (!isset($sp['entityId']) || empty($sp['entityId'])) {
                $errors[] = 'sp_entityId_not_found';
            }

            if (!isset($sp['assertionConsumerService'])
                || !isset($sp['assertionConsumerService']['url'])
                || empty($sp['assertionConsumerService']['url'])
            ) {
                $errors[] = 'sp_acs_not_found';
            } else if (!filter_var($sp['assertionConsumerService']['url'], FILTER_VALIDATE_URL)) {
                $errors[] = 'sp_acs_url_invalid';
            }

            if (isset($sp['singleLogoutService'])
                && isset($sp['singleLogoutService']['url'])
                && !filter_var($sp['singleLogoutService']['url'], FILTER_VALIDATE_URL)
            ) {
                $errors[] = 'sp_sls_url_invalid';
            }

            if (isset($security['signMetadata']) && is_array($security['signMetadata'])) {
                if ((!isset($security['signMetadata']['keyFileName'])
                    || !isset($security['signMetadata']['certFileName'])) &&
                    (!isset($security['signMetadata']['privateKey'])
                    || !isset($security['signMetadata']['x509cert']))
                ) {
                    $errors[] = 'sp_signMetadata_invalid';
                }
            }

            if (((isset($security['authnRequestsSigned']) && $security['authnRequestsSigned'])
                || (isset($security['logoutRequestSigned']) && $security['logoutRequestSigned'])
                || (isset($security['logoutResponseSigned']) && $security['logoutResponseSigned'])
                || (isset($security['wantAssertionsEncrypted']) && $security['wantAssertionsEncrypted'])
                || (isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted']))
                && !$this->checkSPCerts()
            ) {
                $errors[] = 'sp_certs_not_found_and_required';
            }
        }

        if (isset($settings['contactPerson'])) {
            $types = array_keys($settings['contactPerson']);
            $validTypes = ['technical', 'support', 'administrative', 'billing', 'other'];
            foreach ($types as $type) {
                if (!in_array($type, $validTypes)) {
                    $errors[] = 'contact_type_invalid';
                    break;
                }
            }

            foreach ($settings['contactPerson'] as $type => $contact) {
                if (!isset($contact['givenName']) || empty($contact['givenName'])
                    || !isset($contact['emailAddress']) || empty($contact['emailAddress'])
                ) {
                    $errors[] = 'contact_not_enought_data';
                    break;
                }
            }
        }

        if (isset($settings['organization'])) {
            foreach ($settings['organization'] as $organization) {
                if (!isset($organization['name']) || empty($organization['name'])
                    || !isset($organization['displayname']) || empty($organization['displayname'])
                    || !isset($organization['url']) || empty($organization['url'])
                ) {
                    $errors[] = 'organization_not_enought_data';
                    break;
                }
            }
        }

        return $errors;
    }

    /**
     * Checks if the x509 certs of the SP exists and are valid.
     *
     * @return bool
     */
    public function checkSPCerts(): bool
    {
        $key = $this->getSPkey();
        $cert = $this->getSPcert();
        return (!empty($key) && !empty($cert));
    }

    /**
     * Returns the x509 private key of the SP.
     *
     * @return string SP private key
     */
    public function getSPkey(): string
    {
        $key = null;
        if (isset($this->sp['privateKey']) && !empty($this->sp['privateKey'])) {
            $key = $this->sp['privateKey'];
        } else {
            $keyFile = $this->paths['cert'].'sp.key';

            if (file_exists($keyFile)) {
                $key = file_get_contents($keyFile);
            }
        }
        return $key;
    }

    /**
     * Returns the x509 public cert of the SP.
     *
     * @return string SP public cert
     */
    public function getSPcert(): string
    {
        $cert = null;

        if (isset($this->sp['x509cert']) && !empty($this->sp['x509cert'])) {
            $cert = $this->sp['x509cert'];
        } else {
            $cert = "MIIDqDCCApCgAwIBAgIGAYjgaLegMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi04MTI2MTQ4ODEcMBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTAeFw0yMzA2MjIwMDAxMTlaFw0zMzA2MjIwMDAyMTlaMIGUMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxFTATBgNVBAMMDGRldi04MTI2MTQ4ODEcMBoGCSqGSIb3DQEJARYNaW5mb0Bva3RhLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKaHl/tGc1sL0yQzmeGK272eqM6sximwnMkRkfeSBLRZHHaAgLBETuUrGQhDCT0FdnJoOOkgADSyywQQ0X2nndIiraPRYWI9afx1Z0/foe0Ku0bMMniGr5781O229dexvFxSXwwRZtE6We/v4H6vbygAykNflLsyZnL7YZnvEVjOBjjpXsN6j4MKcH+UXbStVwq2U5d6we2b98hfhZ7CBJTK1FC8jG+PiTaFDe06rkiys6VVvCTpnQSFQBbGqf1v+uJwg3VK4l4zLuFGriEjEKwmROer6lf0nJHERwG0521ntwfMgRx5fCOCaVJNIdfrMMri5luB3VMn19MJ0uu0Qo0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEARrudpd8BoSCLYxsXk/P90TJ22vPmRJSKltFNDh3ssVJuaqfa3Bfl5Jtd6MjsvTDcavo1y3N++CjKTytveBQPjsF+vrDmHO9fo4m4b8Orh54j5cAAMcaI+0yYrk/C0QwgUNOteOEmud9yDoVVn/BSHmBqzvLN5fDQCY4kxbB/NHTGPwv6hgjm+1RHk20UdW6AHnGNKr7pfj7enUBXwSd4DKnt/Nnip3YRhpxtdvbBNa69oV92dGOpy9Ex8gRW/kEhaoGDgu9gBnZnkegD0If457KCeRi3ZoFurn5g9rPXr7+10EIWoSLWWNU6NG7SCH2NEEEGOSY6a2BpJuRWMklfag==";
        }

        return $cert;
    }

    /**
     * Returns the x509 public of the SP that is
     * planed to be used soon instead the other
     * public cert
     * @return string SP public cert New
     */
    public function getSPcertNew()
    {
        return "";
        $cert = null;

        if (isset($this->sp['x509certNew']) && !empty($this->sp['x509certNew'])) {
            $cert = $this->sp['x509certNew'];
        } else {
            $certFile = $this->paths['cert'].'sp_new.crt';

            if (file_exists($certFile)) {
                $cert = file_get_contents($certFile);
            }
        }
        return $cert;
    }

    /**
     * Gets the IdP data.
     *
     * @return array  IdP info
     */
    public function getIdPData()
    {
        return $this->idp;
    }

    /**
     * Gets the SP data.
     *
     * @return array  SP info
     */
    public function getSPData()
    {
        return $this->sp;
    }

    /**
     * Gets security data.
     *
     * @return array  SP info
     */
    public function getSecurityData()
    {
        return $this->security;
    }

    /**
     * Gets contact data.
     *
     * @return array  SP info
     */
    public function getContacts()
    {
        return $this->contacts;
    }

    /**
     * Gets organization data.
     *
     * @return array  SP info
     */
    public function getOrganization()
    {
        return $this->organization;
    }

    /**
     * Should SAML requests be compressed?
     *
     * @return bool Yes/No as True/False
     */
    public function shouldCompressRequests()
    {
        return $this->compress['requests'];
    }

    /**
     * Should SAML responses be compressed?
     *
     * @return bool Yes/No as True/False
     */
    public function shouldCompressResponses()
    {
        return $this->compress['responses'];
    }

    /**
     * Gets the IdP SSO url.
     *
     * @return string|null The url of the IdP Single Sign On Service
     */
    public function getIdPSSOUrl()
    {
        $ssoUrl = null;
        if (isset($this->idp['singleSignOnService']) && isset($this->idp['singleSignOnService']['url'])) {
            $ssoUrl = $this->idp['singleSignOnService']['url'];
        }
        return $ssoUrl;
    }

    /**
     * Gets the IdP SLO url.
     *
     * @return string|null The request url of the IdP Single Logout Service
     */
    public function getIdPSLOUrl()
    {
        $sloUrl = null;
        if (isset($this->idp['singleLogoutService']) && isset($this->idp['singleLogoutService']['url'])) {
            $sloUrl = $this->idp['singleLogoutService']['url'];
        }
        return $sloUrl;
    }

    /**
     * Gets the IdP SLO response url.
     *
     * @return string|null The response url of the IdP Single Logout Service
     */
    public function getIdPSLOResponseUrl()
    {
        if (isset($this->idp['singleLogoutService']) && isset($this->idp['singleLogoutService']['responseUrl'])) {
            return $this->idp['singleLogoutService']['responseUrl'];
        }
        return $this->getIdPSLOUrl();
    }

    /**
     * Gets the SP metadata. The XML representation.
     *
     * @param bool $alwaysPublishEncryptionCert When 'true', the returned metadata
     *   will always include an 'encryption' KeyDescriptor. Otherwise, the 'encryption'
     *   KeyDescriptor will only be included if $advancedSettings['security']['wantNameIdEncrypted']
     *   or $advancedSettings['security']['wantAssertionsEncrypted'] are enabled.
     * @param DateTime|null $validUntil    Metadata's valid time
     * @param int|null      $cacheDuration Duration of the cache in seconds
     *
     * @return string  SP metadata (xml)
     *
     * @throws Exception
     * @throws Error
     */
    public function getSPMetadata(
        $alwaysPublishEncryptionCert = false,
        $validUntil = null,
        $cacheDuration = null
    ): string {
        $metadata = Metadata::builder(
            $this->sp,
            $this->security['authnRequestsSigned'],
            $this->security['wantAssertionsSigned'],
            $validUntil,
            $cacheDuration,
            $this->getContacts(),
            $this->getOrganization()
        );

        $certNew = $this->getSPcertNew();
        if (!empty($certNew)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $certNew,
                $alwaysPublishEncryptionCert || $this->security['wantNameIdEncrypted']
                || $this->security['wantAssertionsEncrypted']
            );
        }

        $cert = $this->getSPcert();
        if (!empty($cert)) {
            $metadata = Metadata::addX509KeyDescriptors(
                $metadata,
                $cert,
                $alwaysPublishEncryptionCert || $this->security['wantNameIdEncrypted']
                || $this->security['wantAssertionsEncrypted']
            );
        }

        //Sign Metadata
        if (isset($this->security['signMetadata']) && $this->security['signMetadata'] !== false) {
            if ($this->security['signMetadata'] === true) {
                $keyMetadata = $this->getSPkey();
                $certMetadata = $cert;
                if (!$keyMetadata) {
                    throw new Error(
                        'SP Private key not found.',
                        Error::PRIVATE_KEY_FILE_NOT_FOUND
                    );
                }
                if (!$certMetadata) {
                    throw new Error(
                        'SP Public cert not found.',
                        Error::PUBLIC_CERT_FILE_NOT_FOUND
                    );
                }
            } elseif (isset($this->security['signMetadata']['keyFileName']) &&
                isset($this->security['signMetadata']['certFileName'])) {
                $keyFileName = $this->security['signMetadata']['keyFileName'];
                $certFileName = $this->security['signMetadata']['certFileName'];
                $keyMetadataFile = $this->paths['cert'].$keyFileName;
                $certMetadataFile = $this->paths['cert'].$certFileName;
                if (!file_exists($keyMetadataFile)) {
                    throw new Error(
                        'SP Private key file not found: %s',
                        Error::PRIVATE_KEY_FILE_NOT_FOUND,
                        [$keyMetadataFile]
                    );
                }
                if (!file_exists($certMetadataFile)) {
                    throw new Error(
                        'SP Public cert file not found: %s',
                        Error::PUBLIC_CERT_FILE_NOT_FOUND,
                        [$certMetadataFile]
                    );
                }
                $keyMetadata = file_get_contents($keyMetadataFile);
                $certMetadata = file_get_contents($certMetadataFile);
            } elseif (isset($this->security['signMetadata']['privateKey']) &&
                isset($this->security['signMetadata']['x509cert'])) {
                $keyMetadata = $this->utils->formatPrivateKey($this->security['signMetadata']['privateKey']);
                $certMetadata = $this->utils->formatCert($this->security['signMetadata']['x509cert']);
                if (!$keyMetadata) {
                    throw new Error(
                        'Private key not found.',
                        Error::PRIVATE_KEY_FILE_NOT_FOUND
                    );
                }
                if (!$certMetadata) {
                    throw new Error(
                        'Public cert not found.',
                        Error::PUBLIC_CERT_FILE_NOT_FOUND
                    );
                }
            } else {
                throw new Error(
                    'Invalid Setting: signMetadata value of the sp is not valid',
                    Error::SETTINGS_INVALID_SYNTAX
                );
            }

            $signatureAlgorithm = $this->security['signatureAlgorithm'];
            $digestAlgorithm = $this->security['digestAlgorithm'];
            $metadata = Metadata::signMetadata(
                $metadata,
                $keyMetadata,
                $certMetadata,
                $signatureAlgorithm,
                $digestAlgorithm
            );
        }
        return $metadata;
    }

    /**
     * Validates an XML SP Metadata.
     *
     * @param string $xml Metadata's XML that will be validate
     *
     * @return Array The list of found errors
     *
     * @throws Exception
     */
    public function validateMetadata($xml)
    {
        assert('is_string($xml)');

        $errors = [];
        $res = $this->utils->validateXML($xml, 'saml-schema-metadata-2.0.xsd', $this->debug, $this->getSchemasPath());
        if (!$res instanceof DOMDocument) {
            $errors[] = $res;
        } else {
            $dom = $res;
            $element = $dom->documentElement;
            if ($element->tagName !== 'md:EntityDescriptor') {
                $errors[] = 'noEntityDescriptor_xml';
            } else {
                $validUntil = $cacheDuration = $expireTime = null;

                if ($element->hasAttribute('validUntil')) {
                    $validUntil = $this->utils->parseSAML2Time($element->getAttribute('validUntil'));
                }
                if ($element->hasAttribute('cacheDuration')) {
                    $cacheDuration = $element->getAttribute('cacheDuration');
                }

                $expireTime = $this->utils->getExpireTime($cacheDuration, $validUntil);
                if (isset($expireTime) && time() > $expireTime) {
                    $errors[] = 'expired_xml';
                }
            }
        }

        // TODO: Support Metadata Sign Validation

        return $errors;
    }

    /**
     * Formats the IdP cert.
     */
    public function formatIdPCert()
    {
        if (isset($this->idp['x509cert'])) {
            $this->idp['x509cert'] = $this->utils->formatCert($this->idp['x509cert']);
        }
    }

    /**
     * Formats the Multple IdP certs.
     */
    public function formatIdPCertMulti()
    {
        if (isset($this->idp['x509certMulti'])) {
            if (isset($this->idp['x509certMulti']['signing'])) {
                foreach ($this->idp['x509certMulti']['signing'] as $i => $cert) {
                    $this->idp['x509certMulti']['signing'][$i] = $this->utils->formatCert($cert);
                }
            }
            if (isset($this->idp['x509certMulti']['encryption'])) {
                foreach ($this->idp['x509certMulti']['encryption'] as $i => $cert) {
                    $this->idp['x509certMulti']['encryption'][$i] = $this->utils->formatCert($cert);
                }
            }
        }
    }

    /**
     * Formats the SP cert.
     */
    public function formatSPCert()
    {
        if (isset($this->sp['x509cert'])) {
            $this->sp['x509cert'] = $this->utils->formatCert($this->sp['x509cert']);
        }
    }

    /**
     * Formats the SP cert.
     */
    public function formatSPCertNew()
    {
        if (isset($this->sp['x509certNew'])) {
            $this->sp['x509certNew'] = $this->utils->formatCert($this->sp['x509certNew']);
        }
    }

    /**
     * Formats the SP private key.
     */
    public function formatSPKey()
    {
        if (isset($this->sp['privateKey'])) {
            $this->sp['privateKey'] = $this->utils->formatPrivateKey($this->sp['privateKey']);
        }
    }

    /**
     * Returns an array with the errors, the array is empty when the settings is ok.
     *
     * @return array Errors
     */
    public function getErrors()
    {
        return $this->errors;
    }

    /**
     * Activates or deactivates the strict mode.
     *
     * @param bool $value Strict parameter
     *
     * @throws Exception
     */
    public function setStrict($value)
    {
        if (!is_bool($value)) {
            throw new Exception('Invalid value passed to setStrict()');
        }

        $this->strict = $value;
    }

    /**
     * Returns if the 'strict' mode is active.
     *
     * @return bool Strict parameter
     */
    public function isStrict()
    {
        return $this->strict;
    }

    /**
     * Returns if the debug is active.
     *
     * @return bool Debug parameter
     */
    public function isDebugActive()
    {
        return $this->debug;
    }

    /**
     * Set a baseurl value.
     *
     * @param $baseurl
     */
    public function setBaseURL($baseurl)
    {
        $this->baseurl = $baseurl;
    }

    /**
     * Returns the baseurl set on the settings if any.
     *
     * @return null|string The baseurl
     */
    public function getBaseURL()
    {
        return $this->baseurl;
    }

    /**
     * Sets the IdP certificate.
     *
     * @param string $cert IdP certificate
     */
    public function setIdPCert($cert)
    {
        $this->idp['x509cert'] = $cert;
        $this->formatIdPCert();
    }
}
