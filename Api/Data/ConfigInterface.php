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

namespace GumNet\SSO\Api\Data;

interface ConfigInterface
{
    // Scope config paths
    public const SOCPE_CONFIG_BASE = 'single_sign_on/sso/';
    public const SCOPE_CONFIG_ENABLE = self::SOCPE_CONFIG_BASE . 'enable';
    public const SCOPE_CONFIG_ISSUER = self::SOCPE_CONFIG_BASE . 'issuer';
    public const SCOPE_CONFIG_SIGN_ON_URL = self::SOCPE_CONFIG_BASE . 'sign_on_url';
    public const SCOPE_CONFIG_SIGN_OUT_URL = self::SOCPE_CONFIG_BASE . 'sign_out_url';
    public const SCOPE_CONFIG_X509_CERT = self::SOCPE_CONFIG_BASE . 'x509_cert';

    // Settings array entries
    public const SETTINGS_SP = 'sp';
    public const SETTINGS_ENTITY_ID = 'entityId';
    public const SETTINGS_ASSERTION_CONSUMER_SERVICE = 'assertionConsumerService';
    public const SETTINGS_SINGLE_LOGOUT_SERVICE = 'singleLogoutService';
    public const SETTINGS_NAME_ID_FORMAT = 'NameIDFormat';
    public const SETTINGS_IDP = 'idp';
    public const SETTINGS_SINGLE_SIGN_ON_SERVICE = 'singleSignOnService';
    public const SETTINGS_X509CERT = 'x509cert';
    public const URL = 'url';
}
