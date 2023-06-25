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

namespace GumNet\SSO\Controller\Sso;

use GumNet\SSO\Helper\Data;
use GumNet\SSO\Model\Saml2\Auth;
use Magento\Framework\App\Action\Context;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\CsrfAwareActionInterface;
use Magento\Framework\App\Request\InvalidRequestException;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Redirect;
use Magento\Framework\Controller\Result\RedirectFactory;
use Magento\Framework\Stdlib\Cookie\CookieMetadataFactory;
use Magento\Framework\Stdlib\CookieManagerInterface;

class Index implements HttpGetActionInterface, HttpPostActionInterface, CsrfAwareActionInterface
{
    /**
     * @param Context $context
     * @param Auth $auth
     * @param Data $helper
     * @param RedirectFactory $redirectFactory
     */
    public function __construct(
        private readonly Context $context,
        private readonly Auth $auth,
        private readonly Data $helper,
        private readonly RedirectFactory $redirectFactory,
        private readonly CookieManagerInterface $cookieManager,
        private readonly CookieMetadataFactory $cookieMetadataFactory
    ) {
    }

    /**
     * @inheritDoc
     */
    public function execute(): Redirect
    {
        $this->prepareAuth();
        if ($samlResponse = $this->context->getRequest()->getParam('SAMLResponse', '')) {
            return $this->processSignOn($samlResponse);
        }
        return $this->redirectToSso();
    }



    public function processSignOn(string $samlResponse): Redirect
    {
        $this->auth->processResponse($samlResponse, $this->auth->getSettings(), $this->getCookie());
        echo $this->auth->getNameId();
        die();
    }

    public function redirectToSso(): Redirect
    {
        /** @var Redirect $result */
        $result = $this->redirectFactory->create();
        $url = $this->auth->login();
        echo $this->auth->getLastRequestID();
        $this->createCookie($this->auth->getLastRequestID());
        return $result->setUrl($url);
    }

    public function createCookie(string $value): void
    {
        $cookieMetadata = $this->cookieMetadataFactory->createPublicCookieMetadata();
        $cookieMetadata->setDuration(1800);
        $cookieMetadata->setPath('/');
        $cookieMetadata->setHttpOnly(false);
        $this->cookieManager->setPublicCookie('sso_id', $value, $cookieMetadata);
    }

    public function getCookie()
    {
        return $this->cookieManager->getCookie('/sso_id');
    }

    /**
     * Set authenticator settings
     *
     * @return void
     */
    public function prepareAuth(): void
    {
        $this->auth->loadSettingsFromArray($this->helper->getSettingsArray());
    }

    public function createCsrfValidationException(RequestInterface $request): ?InvalidRequestException
    {
        return new InvalidRequestException('Error');
    }

    public function validateForCsrf(RequestInterface $request): ?bool
    {
        return true;
    }
}
