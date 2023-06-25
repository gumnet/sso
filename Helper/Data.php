<?php
/**
 * @author Gustavo Ulyssea - gustavo.ulyssea@gmail.com
 * @copyright Copyright (c) 2023 GumNet (https://gum.net.br)
 * @package GumNet SSO
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY GUM Net (https://gum.net.br). AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace GumNet\SSO\Helper;

use GumNet\SSO\Api\Data\ConfigInterface;
use Magento\Framework\App\Helper\Context;

class Data
{
    /**
     * @param Context $context
     */
    public function __construct(
        private readonly Context $context
    ) {
    }

    /**
     * Get config from core_config_data
     *
     * @param string $path
     * @return string
     */
    public function getConfig(string $path): string
    {
        return $this->context->getScopeConfig()->getValue($path);
    }

    /**
     * Get Magento base URL
     *
     * @return string
     */
    public function getBaseUrl(): string
    {
        return $this->context->getUrlBuilder()->getBaseUrl();
    }

    /**
     * Get settings array for Saml2\Settings
     *
     * @return array
     */
    public function getSettingsArray(): array
    {
        return [
            ConfigInterface::SETTINGS_SP => [
                ConfigInterface::SETTINGS_ENTITY_ID => $this->getBaseUrl() . 'single_sign_on/metadata',
                ConfigInterface::SETTINGS_ASSERTION_CONSUMER_SERVICE => [
                    ConfigInterface::URL => $this->getBaseUrl() . 'sso?acs',
                ],
                ConfigInterface::SETTINGS_SINGLE_LOGOUT_SERVICE => [
                    ConfigInterface::URL => $this->getBaseUrl() . 'sso?sls',
                ],
                ConfigInterface::SETTINGS_NAME_ID_FORMAT => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            ],
            ConfigInterface::SETTINGS_IDP => [
                ConfigInterface::SETTINGS_ENTITY_ID => $this->getConfig(ConfigInterface::SCOPE_CONFIG_ISSUER),
                ConfigInterface::SETTINGS_SINGLE_SIGN_ON_SERVICE => [
                    ConfigInterface::URL => $this->getConfig(ConfigInterface::SCOPE_CONFIG_SIGN_ON_URL)
                ],
                ConfigInterface::SETTINGS_SINGLE_LOGOUT_SERVICE => [
                    ConfigInterface::URL => $this->getConfig(ConfigInterface::SCOPE_CONFIG_SIGN_OUT_URL)
                ],
                ConfigInterface::SETTINGS_X509CERT => $this->getConfig(ConfigInterface::SCOPE_CONFIG_X509_CERT)
            ],
        ];
    }
}
