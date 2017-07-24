<?php

namespace SimpleUser;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Silex\Application;
use SimpleUser\User;

class EditUserVoter extends Voter
{

    protected $container;

    public function __construct(\Silex\Application $app)
    {
        $this->container = $app;
    }

    protected function getDecisionManager()
    {
        return $this->container['security.access_manager'];
    }

    const EDIT = 'EDIT_USER';
    const EDIT_ID = 'EDIT_USER_ID';

    protected function supports($attribute, $subject)
    {
        return ( $subject instanceof User || is_numeric($subject) ) && in_array($attribute, array(
            self::EDIT, self::EDIT_ID
        ));
    }

    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        $user = $token->getUser();
        if (!$user instanceof User) {
            return false;
        }

        if ($this->getDecisionManager()->decide($token, array('ROLE_ADMIN'))) {
            return true;
        }

        if ($attribute == self::EDIT) {
            $user2 = $subject;
            return $this->usersHaveSameId($user, $user2) ? true : false;
        }

        if ($attribute == self::EDIT_ID) {
            $id = $subject;
            return $this->hasUserId($user, $id) ? true : false;
        }

        return false;
    }

    protected function hasUserId($user, $id)
    {
        return $user instanceof User
            && $id > 0
            && $user->getId() == $id;
    }

    protected function usersHaveSameId($user1, $user2)
    {
        return $user1 instanceof User
            && $user2 instanceof User
            && $user1->getId() > 0
            && $user1->getId() == $user2->getId();
    }

}