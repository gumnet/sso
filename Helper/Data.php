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
use Magento\Backend\Model\Auth\Session;
use Magento\Backend\Model\Session\AdminConfig;
use Magento\Backend\Model\UrlInterface;
use Magento\Framework\App\Area;
use Magento\Framework\App\Helper\Context;
use Magento\Framework\App\ObjectManager;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\State;
use Magento\Framework\Exception\InputException;
use Magento\Framework\ObjectManager\ConfigLoaderInterface;
use Magento\Framework\Stdlib\Cookie\CookieMetadataFactory;
use Magento\Framework\Stdlib\Cookie\CookieSizeLimitReachedException;
use Magento\Framework\Stdlib\Cookie\FailureToSendException;
use Magento\Framework\Stdlib\CookieManagerInterface;
use Magento\Security\Model\AdminSessionsManager;
use Magento\Store\Model\App\Emulation;
use Magento\User\Model\ResourceModel\User\CollectionFactory;
use Magento\Authorization\Model\ResourceModel\Role\CollectionFactory as RoleCollectionFactory;
use Magento\Backend\Model\Auth\StorageInterface as AuthStorageInterface;
use Magento\Framework\Event\ManagerInterface;
use Magento\Framework\Math\Random;
use Magento\User\Model\ResourceModel\User as UserResource;
use Magento\User\Model\User;

class Data
{
    public function __construct(
        private readonly Context                $context,
        private readonly Session                $session,
        private readonly CollectionFactory      $userCollectionFactory,
        private readonly UrlInterface           $backendUrl,
        private readonly CookieManagerInterface $cookieManager,
        private readonly CookieMetadataFactory  $cookieMetadataFactory,
        private readonly AdminConfig            $sessionConfig,
        private readonly AdminSessionsManager   $adminSessionsManager,
        private readonly Emulation              $emulation,
        private readonly User                   $user,
        private readonly UserResource           $userResource,
        private readonly RoleCollectionFactory  $roleCollectionFactory,
        private readonly Random                 $random,
        private readonly AuthStorageInterface   $authStorage,
        private readonly AdminSessionsManager   $securityManager,
        private readonly ManagerInterface       $eventManager

    ) {
    }

    /**
     * Get base admin url
     *
     * @return string
     */
    public function getAdminUrl(): string
    {
        return $this->backendUrl->getUrl('admin');
    }

    /**
     * Login admin user by email
     *
     * @param string $email
     * @return void
     * @throws InputException
     * @throws CookieSizeLimitReachedException
     * @throws FailureToSendException
     */
    public function adminLogin(string $email): void
    {
        $userCollection = $this->userCollectionFactory->create();
        /** @var \Magento\User\Model\User $user */
        $user = $userCollection
            ->addFieldToFilter('email', ['eq' => $email])
            ->addFieldToSelect('*')
            ->getFirstItem();

        if ((int)$user->getIsActive() !== 1) {
            throw new \Exception(__('User account is inactive. Please contact the store administrator.'));
        }
        $this->authStorage->setUser($user);
        $this->authStorage->processLogin();
        $this->userResource->recordLogin($user);
        $this->securityManager->processLogin();
        if (!$this->authStorage->getUser()) {
            throw new \Exception(__('Sign in process failed - your account may be disabled temporarily. Please contact the store administrator.'));
        }
        $this->eventManager->dispatch(
            'backend_auth_user_login_success',
            ['user' => $user]
        );
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
