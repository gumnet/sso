<?php

namespace GumNet\SSO\Model;

use Magento\Authorization\Model\ResourceModel\Role\CollectionFactory as RoleCollectionFactory;
use Magento\Backend\Model\Auth\StorageInterface as AuthStorageInterface;
use Magento\Framework\Event\ManagerInterface;
use Magento\Framework\Exception\InputException;
use Magento\Framework\Math\Random;
use Magento\Framework\Stdlib\Cookie\CookieSizeLimitReachedException;
use Magento\Framework\Stdlib\Cookie\FailureToSendException;
use Magento\Security\Model\AdminSessionsManager;
use Magento\Store\Model\App\Emulation;
use Magento\User\Model\ResourceModel\User as UserResource;
use Magento\User\Model\ResourceModel\User\CollectionFactory;

class User
{
    public function __construct(
        private readonly CollectionFactory $userCollectionFactory,
        private readonly AuthStorageInterface $authStorage,
        private readonly ManagerInterface $eventManager,
        private readonly UserResource $userResource,
        private readonly AdminSessionsManager   $securityManager,
        private readonly RoleCollectionFactory  $roleCollectionFactory,
        private readonly Random $random,
        private readonly Emulation $emulation
    ) {
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
    public function login(string $email): void
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
            $message = <<<MSG
'Sign in process failed - your account may be disabled temporarily. Please contact the store administrator.'
MSG;
            throw new \Exception(__($message));
        }
        $this->eventManager->dispatch(
            'backend_auth_user_login_success',
            ['user' => $user]
        );
    }
}
