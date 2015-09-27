<?php

class SSLClientAuthHooks {
    private static function parseDistinguishedName($dn) {
        $res = array();

        $split = explode('/', $dn);

        foreach ($split as $x) {
            $exploded = explode('=', $x, 2);
            if (count($exploded) !== 2) continue;

            $res[$exploded[0]] = $exploded[1];
        }

        return $res;
    }

    public static function onUserLoadFromSession ($user, &$result) {
        $result = false; // don't attempt default auth process

        if (!isset($_SERVER['SSL_CLIENT_S_DN'])) {
            return true;
        }

        $parsed = self::parseDistinguishedName($_SERVER['SSL_CLIENT_S_DN']);
        if (!isset($parsed['CN'])) {
            return true;
        } 

        $userName = $parsed['CN'];

        $localId = User::idFromName($userName);

        if ($localId === null) {
            // local user doesn't exists yet

            $user->loadDefaults($parsed['CN']);
            
            if (!User::isCreatableName($user->getName())) {
                wfDebug(__METHOD__ . ": Invalid username\n");
                return true;
            }

            $user->addToDatabase();

            if (isset($parsed['emailAddress'])) {
                $user->setEmail($parsed['emailAddress']);
            }

            $user->saveSettings();

            $user->addNewUserLogEntryAutoCreate();

            Hooks::run( 'AuthPluginAutoCreate', array( $user ) );

            DeferredUpdates::addUpdate( new SiteStatsUpdate( 0, 0, 0, 0, 1 ) );
        } else {
            $user->setID($localId);
            $user->loadFromId();
        }

        global $wgUser;
        $wgUser = &$user;

        $result = true; // this also aborts default auth process
        return true; 
    }

    public static function onPersonalUrls(array &$personal_urls, Title $title, SkinTemplate $skin) {
        unset($personal_urls['createaccount']);
        unset($personal_urls['login']);
        unset($personal_urls['anonlogin']);
        unset($personal_urls['logout']);
    }

    public static function onUserLogout(&$user) {
        // no, you can't, lol
        return false;
    }
};
