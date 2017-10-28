<?php
/**
 * AuthSSO.php
 *
 * -Description-
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @package    LibreNMS
 * @link       http://librenms.org
 * @copyright  2017 Adam Bishop
 * @author     Adam Bishop <adam@omega.org.uk>
 */

namespace LibreNMS\Tests;

class AuthSSOTest extends DBTestCase
{
    private $last_user = null;

    // Set up an SSO config for tests
    public function basicConfig() {
        global $config;

        $config['sso']['mode'] = 'env';
        $config['sso']['create_users'] = true;
        $config['sso']['update_users'] = true;
        $config['sso']['trusted_proxies'] = ['127.0.0.1', '::1'];
        $config['sso']['user_attr'] = 'REMOTE_USER';
        $config['sso']['realname_attr'] = 'displayName';
        $config['sso']['email_attr'] = 'mail';
        $config['sso']['descr_attr'] = null;
        $config['sso']['level_attr'] = null;
        $config['sso']['group_strategy'] = 'static';
        $config['sso']['group_attr'] = 'member';
        $config['sso']['group_filter'] = '/(.*)/i';
        $config['sso']['group_delimiter'] = ';';
        $config['sso']['group_level_map'] = null;
        $config['sso']['static_level'] = -1;
    }

    // Set up $_SERVER in env mode
    public function basicEnvironmentEnv() {
        global $config;
        unset($_SERVER);

        $config['sso']['mode'] = 'env';

        $_SERVER['REMOTE_ADDR'] = '::1';
        $_SERVER['REMOTE_USER'] = 'test';

        $_SERVER['mail'] = 'test@example.org';
        $_SERVER['displayName'] = $this->makeBreakUser();
    }


    // Set up $_SERVER in header mode
    public function basicEnvironmentHeader() {
        global $config;
        unset($_SERVER);

        $config['sso']['mode'] = 'header';

        $_SERVER['REMOTE_ADDR'] = '::1';
        $_SERVER['REMOTE_USER'] = $this->makeBreakUser();

        $_SERVER['HTTP_MAIL'] = 'test@example.org';
        $_SERVER['HTTP_DISPLAYNAME'] = 'Test User';
    }

    public function makeBreakUser() {
        $this->breakUser();

        $u = bin2hex(openssl_random_pseudo_bytes(16));
        $this->last_user = $u;
        $_SERVER['REMOTE_USER'] = $u;

        return $u;
    }

    public function breakUser() {
        if ($this->last_user !== null) {
            $r = deluser(get_userid($this->last_user));
            $this->last_user = null;
            return $r;
        }

        return true;
    }

    // Excercise general auth flow
    public function testValidAuthNoCreateUpdate() {
        global $config;

        $this->basicConfig();

        $config['sso']['create_users'] = false;
        $config['sso']['update_users'] = false;

        // Create a random username and store it with the defaults
        $this->basicEnvironmentEnv();
        $user = $this->makeBreakUser();
        $this->assertTrue(authenticate($user, NULL));

        // Retrieve it and validate
        $dbuser = get_user(get_userid($user));
        $this->assertFalse(auth_sso_get_attr($config['sso']['realname_attr']) === $dbuser['realname']);
        $this->assertFalse($dbuser['level'] === "0");
        $this->assertFalse(auth_sso_get_attr($config['sso']['email_attr']) === $dbuser['email']);
    }

    // Excercise general auth flow with creation enabled
    public function testValidAuthCreateOnly() {
        global $config;

        $this->basicConfig();
        $config['sso']['create_users'] = true;
        $config['sso']['update_users'] = false;

        // Create a random username and store it with the defaults
        $this->basicEnvironmentEnv();
        $user = $this->makeBreakUser();
        $this->assertTrue(authenticate($user, NULL));

        // Retrieve it and validate
        $dbuser = get_user(get_userid($user));
        $this->assertTrue(auth_sso_get_attr($config['sso']['realname_attr']) === $dbuser['realname']);
        $this->assertTrue($dbuser['level'] === "-1");
        $this->assertTrue(auth_sso_get_attr($config['sso']['email_attr']) === $dbuser['email']);

        // Change a few things and reauth
        $_SERVER['mail'] = 'test@example.net';
        $_SERVER['displayName'] = 'Testier User';
        $config['sso']['static_level'] = 10;
        $this->assertTrue(authenticate($user, NULL));

        // Retrieve it and validate the update was not persisted
        $dbuser = get_user(get_userid($user));
        $this->assertFalse(auth_sso_get_attr($config['sso']['realname_attr']) === $dbuser['realname']);
        $this->assertFalse($dbuser['level'] === "10");
        $this->assertFalse(auth_sso_get_attr($config['sso']['email_attr']) === $dbuser['email']);
    }

    // Excercise general auth flow with updates enabled
    public function testValidAuthUpdate() {
        global $config;

        $this->basicConfig();

        // Create a random username and store it with the defaults
        $this->basicEnvironmentEnv();
        $user = $this->makeBreakUser();
        $this->assertTrue(authenticate($user, NULL));

        // Change a few things and reauth
        $_SERVER['mail'] = 'test@example.net';
        $_SERVER['displayName'] = 'Testier User';
        $config['sso']['static_level'] = 10;
        $this->assertTrue(authenticate($user, NULL));

        // Retrieve it and validate the update persisted
        $dbuser = get_user(get_userid($user));
        $this->assertTrue(auth_sso_get_attr($config['sso']['realname_attr']) === $dbuser['realname']);
        $this->assertTrue($dbuser['level'] === "10");
        $this->assertTrue(auth_sso_get_attr($config['sso']['email_attr']) === $dbuser['email']);
    }

    // Check some invalid authentication modes
    public function testBadAuth() {
        global $config;

        $this->basicConfig();
        $this->basicEnvironmentEnv();
        unset($_SERVER);

        $this->setExpectedException('LibreNMS\Exceptions\AuthenticationException');
        authenticate(NULL, NULL);

        $this->basicEnvironmentHeader();
        unset($_SERVER);

        $this->setExpectedException('LibreNMS\Exceptions\AuthenticationException');
        authenticate(NULL, NULL);
    }

    // Test some missing attributes
    public function testNoAttribute() {
        global $config;

        $this->basicConfig();
        $this->basicEnvironmentEnv();
        unset($_SERVER['displayName']);
        unset($_SERVER['mail']);

        $this->assertTrue(authenticate($this->makeBreakUser(), NULL));

        $this->basicEnvironmentHeader();
        unset($_SERVER['HTTP_DISPLAYNAME']);
        unset($_SERVER['HTTP_MAIL']);

        $this->assertTrue(authenticate($this->makeBreakUser(), NULL));
    }

    // Document the modules current behaviour, so that changes trigger test failures
    public function testCapabilityFunctions() {
        $this->assertNull(init_auth());
        $this->assertFalse(reauthenticate(NULL, NULL));
        $this->assertFalse(passwordscanchange());
        $this->assertFalse(changepassword());
        $this->assertTrue(auth_usermanagement());
        $this->assertTrue(can_update_users());
        $this->assertTrue(auth_external());
    }

    /* Everything from here comprises of targeted tests to excercise single methods */

    public function testGetExternalUserName() {
    global $config;

        $this->basicConfig();

        $this->basicEnvironmentEnv();
        $this->assertInternalType('string', get_external_username());

        // Missing
        unset($_SERVER['REMOTE_USER']);
        $this->assertNull(get_external_username());
        $this->basicEnvironmentEnv();

        // Missing pointer to attribute
        unset($config['sso']['user_attr']);
        $this->assertNull(get_external_username());
        $this->basicEnvironmentEnv();

        // Non-existant attribute
        $config['sso']['user_attr'] = 'foobar';
        $this->assertNull(get_external_username());
        $this->basicEnvironmentEnv();

        // NULL pointer to attribute
        $config['sso']['user_attr'] = NULL;
        $this->assertNull(get_external_username());
        $this->basicEnvironmentEnv();

        // NULL attribute
        $config['sso']['user_attr'] = 'REMOTE_USER';
        $_SERVER['REMOTE_USER'] = NULL;
        $this->assertNull(get_external_username());
    }

    public function testGetAttr() {
        global $config;

        $_SERVER['HTTP_VALID_ATTR'] = 'string';
        $_SERVER['alsoVALID-ATTR'] = 'otherstring';

        $config['sso']['mode'] = 'env';
        $this->assertNull(auth_sso_get_attr('foobar'));
        $this->assertNull(auth_sso_get_attr(NULL));
        $this->assertNull(auth_sso_get_attr(1));
        $this->assertInternalType('string',auth_sso_get_attr('alsoVALID-ATTR'));
        $this->assertInternalType('string',auth_sso_get_attr('HTTP_VALID_ATTR'));

        $config['sso']['mode'] = 'header';
        $this->assertNull(auth_sso_get_attr('foobar'));
        $this->assertNull(auth_sso_get_attr(NULL));
        $this->assertNull(auth_sso_get_attr(1));
        $this->assertNull(auth_sso_get_attr('alsoVALID-ATTR'));
        $this->assertInternalType('string',auth_sso_get_attr('VALID-ATTR'));
    }

    public function testTrustedProxies() {
        global $config;

        $config['sso']['trusted_proxies'] = ['127.0.0.1', '::1', '2001:630:50::/48', '8.8.8.0/25'];

        // v4 valid CIDR
        $_SERVER['REMOTE_ADDR'] = '8.8.8.8';
        $this->assertTrue(auth_sso_proxy_trusted());

        // v4 valid single
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $this->assertTrue(auth_sso_proxy_trusted());

        // v4 invalid CIDR
        $_SERVER['REMOTE_ADDR'] = '9.8.8.8';
        $this->assertFalse(auth_sso_proxy_trusted());

        // v6 valid CIDR
        $_SERVER['REMOTE_ADDR'] = '2001:630:50:baad:beef:feed:face:cafe';
        $this->assertTrue(auth_sso_proxy_trusted());

        // v6 valid single
        $_SERVER['REMOTE_ADDR'] = '::1';
        $this->assertTrue(auth_sso_proxy_trusted());

        // v6 invalid CIDR
        $_SERVER['REMOTE_ADDR'] = '2600::';
        $this->assertFalse(auth_sso_proxy_trusted());

        // Not an IP
        $_SERVER['REMOTE_ADDR'] = 16;
        $this->assertFalse(auth_sso_proxy_trusted());

        //NULL
        $_SERVER['REMOTE_ADDR'] = NULL;
        $this->assertFalse(auth_sso_proxy_trusted());

        // Invalid String
        $_SERVER['REMOTE_ADDR'] = 'Not an IP address at all, but maybe PHP will end up type juggling somehow';
        $this->assertFalse(auth_sso_proxy_trusted());

        // Not a list
        $config['sso']['trusted_proxies'] = '8.8.8.0/25';
        $_SERVER['REMOTE_ADDR'] = '8.8.8.8';
        $this->assertFalse(auth_sso_proxy_trusted());

        // Unset
        unset($_SERVER['REMOTE_ADDR']);
        $this->assertFalse(auth_sso_proxy_trusted());
    }

    public function testLevelCaulculationFromAttr() {
        global $config;

        $config['sso']['mode'] = 'env';
        $config['sso']['group_strategy'] = 'attribute';

        //Integer
        $config['sso']['level_attr'] = 'level';
        $_SERVER['level'] = 9;
        $this->assertTrue(auth_sso_calculate_level() === 9);

        //String
        $config['sso']['level_attr'] = 'level';
        $_SERVER['level'] = "9";
        $this->assertTrue(auth_sso_calculate_level() === 9);

        //Invalid String
        $config['sso']['level_attr'] = 'level';
        $_SERVER['level'] = 'foobar';
        $this->setExpectedException('LibreNMS\Exceptions\AuthenticationException');
        auth_sso_calculate_level();

        //NULL
        $config['sso']['level_attr'] = 'level';
        $_SERVER['level'] = NULL;
        $this->setExpectedException('LibreNMS\Exceptions\AuthenticationException');
        auth_sso_calculate_level();

        //Unset pointer
        unset($config['sso']['level_attr']);
        $_SERVER['level'] = "9";
        $this->setExpectedException('LibreNMS\Exceptions\AuthenticationException');
        auth_sso_calculate_level();

        //Unset attr
        $config['sso']['level_attr'] = 'level';
        unset($_SERVER['level']);
        $this->setExpectedException('LibreNMS\Exceptions\AuthenticationException');
        auth_sso_calculate_level();
    }

    public function testGroupParsing() {
        global $config;

        $this->basicConfig();
        $this->basicEnvironmentEnv();

        $config['sso']['group_strategy'] = 'map';
        $config['sso']['group_delimiter'] = ';';
        $config['sso']['group_attr'] = 'member';
        $config['sso']['group_level_map'] = ['librenms-admins' => 10, 'librenms-readers' => 1, 'librenms-billingcontacts' => 5];
        $_SERVER['member'] = "librenms-admins;librenms-readers;librenms-billingcontacts;unrelatedgroup;confluence-admins";

        // Valid options
        $this->assertTrue(auth_sso_parse_groups() === 10);

        // No match
        $_SERVER['member'] = "confluence-admins";
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Delimiter only
        $_SERVER['member'] = ";;;;";
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Empty
        $_SERVER['member'] = "";
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Null
        $_SERVER['member'] = NULL;
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Unset
        unset($_SERVER['member']);
        $this->assertTrue(auth_sso_parse_groups() === 0);

        $_SERVER['member'] = "librenms-admins;librenms-readers;librenms-billingcontacts;unrelatedgroup;confluence-admins";

        // Empty
        $config['sso']['group_level_map'] = [];
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Not associative
        $config['sso']['group_level_map'] = ['foo', 'bar', 'librenms-admins'];
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Null
        $config['sso']['group_level_map'] = NULL;
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Unset
        unset($config['sso']['group_level_map']);
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // No delimiter
        unset($config['sso']['group_delimiter']);
        $this->assertTrue(auth_sso_parse_groups() === 0);

        // Test group filtering by regex
        $config['sso']['group_filter'] = "/confluence-(.*)/i";
        $config['sso']['group_delimiter'] = ';';
        $config['sso']['group_level_map'] = ['librenms-admins' => 10, 'librenms-readers' => 1, 'librenms-billingcontacts' => 5, 'confluence-admins' => 7];
        $this->assertTrue(auth_sso_parse_groups() === 7);

        // Test group filtering by empty regex
        $config['sso']['group_filter'] = "";
        $this->assertTrue(auth_sso_parse_groups() === 10);

        // Test group filtering by null regex
        $config['sso']['group_filter'] = NULL;
        $this->assertTrue(auth_sso_parse_groups() === 10);
    }

    public function testDeleteUser() {
        // Make sure that no exceptions get thrown, and clean up the final test user
        $this->assertTrue($this->breakUser());
    }
}
