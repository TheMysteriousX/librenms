<?php
/**
 * sso.inc.php
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

use LibreNMS\Config;
use LibreNMS\Util\IP;
use LibreNMS\Exceptions\AuthenticationException;
use LibreNMS\Exceptions\InvalidIpException;

/**
 * Some functionality in this mechanism is inspired by confluence_http_authenticator (@chauth) and graylog-plugin-auth-sso (@Graylog)
 *
 */

function init_auth()
{
    // No initialisation is required
}

function authenticate($username, $password)
{
    if (empty($username)) {
        throw new AuthenticationException('$config[\'sso\'][\'user_attr\'] was not found or was empty');
    }

    // Build the user's details from attributes
    $email = auth_sso_get_attr(Config::get('sso.email_attr'));
    $realname = auth_sso_get_attr(Config::get('sso.realname_attr'));
    $description = auth_sso_get_attr(Config::get('sso.descr_attr'));
    $can_modify_passwd = 0;

    $level = auth_sso_calculate_level();

    // User has already been approved by the authenicator so if automatic user create/update is enabled, do it
    if (Config::get('sso.create_users') && !user_exists($username)) {
        adduser($username, $password, $level, $email, $realname, $can_modify_passwd, $description);
    } elseif (Config::get('sso.update_users') && user_exists($username)) {
        update_user(get_userid($username), $realname, $level, $can_modify_passwd, $email);
    }

    return true;
}

function reauthenticate($sess_id, $token)
{
    // The user is always authenticated when LibreNMS is executing - if this is called, something has gone wrong.
    return false;
}

function passwordscanchange()
{
    // not supported so return 0
    return false;
}


function changepassword()
{
    // not supported so return 0
    return false;
}


function auth_usermanagement()
{
    // Only useful for pre-authorising users
    return true;
}

function adduser($username, $password, $level = 1, $email = '', $realname = '', $can_modify_passwd = 0, $description = 'SSO User')
{
    // Check to see if user is already added in the database
    if (!user_exists($username)) {
        $userid = dbInsert(array('username' => $username, 'password' => null, 'realname' => $realname, 'email' => $email, 'descr' => $description, 'level' => $level, 'can_modify_passwd' => $can_modify_passwd), 'users');

        if ($userid == false) {
            return false;
        } else {
            foreach (dbFetchRows('select notifications.* from notifications where not exists( select 1 from notifications_attribs where notifications.notifications_id = notifications_attribs.notifications_id and notifications_attribs.user_id = ?) order by notifications.notifications_id desc', array($userid)) as $notif) {
                dbInsert(array('notifications_id'=>$notif['notifications_id'],'user_id'=>$userid,'key'=>'read','value'=>1), 'notifications_attribs');
            }
        }
        return $userid;
    } else {
        return false;
    }
}

function user_exists($username)
{
    // A local user is always created, so we query this, as in the event of an admin choosing to manually administer user creation we should return false.
    return dbFetchCell('SELECT COUNT(*) FROM users WHERE username = ?', array(get_external_username()), true);
}


function get_userlevel($username)
{
    // The user level should always be persisted to the database (and may be managed there) so we again query the database.
    return dbFetchCell('SELECT `level` FROM `users` WHERE `username` = ?', array(get_external_username()), true);
}


function get_userid($username)
{
    // User ID is obviously unique to LibreNMS, this must be resolved via the database
    return dbFetchCell('SELECT `user_id` FROM `users` WHERE `username` = ?', array(get_external_username()), true);
}


function deluser($userid)
{
    // Clean up the entries persisted to the database
    dbDelete('bill_perms', '`user_id` =  ?', array($userid));
    dbDelete('devices_perms', '`user_id` =  ?', array($userid));
    dbDelete('ports_perms', '`user_id` =  ?', array($userid));
    dbDelete('users_prefs', '`user_id` =  ?', array($userid));
    dbDelete('users', '`user_id` =  ?', array($userid));

    return dbDelete('users', '`user_id` =  ?', array($userid));
}


function get_userlist()
{
    return dbFetchRows('SELECT * FROM `users` ORDER BY `username`');
}


function can_update_users()
{
    return true;
}


function get_user($user_id)
{
    return dbFetchRow('SELECT * FROM `users` WHERE `user_id` = ?', array($user_id), true);
}


function update_user($user_id, $realname, $level, $can_modify_passwd, $email)
{
    // This could, in the worse case, occur on every single pageload, so try and do a bit of optimisation
    $user = get_user($user_id);

    if ($realname !== $user['realname'] || $level !== $user['level'] || $can_modify_passwd !== $user['can_modify_passwd'] || $email !== $user['email']) {
        dbUpdate(array('realname' => $realname, 'level' => $level, 'can_modify_passwd' => $can_modify_passwd, 'email' => $email), 'users', '`user_id` = ?', array($user_id));
    }
}

/**
 * Indicates if the authentication happens within the LibreNMS process, or external to it.
 * If the former, LibreNMS provides a login form, and supplies the username to the mechanism. If the latter, the authenticator supplies it via get_external_username().
 * This is an important distinction, because at the point this is called if the authentication happens out of process, the user is already authenticated and LibreNMS must not display a login form - even if something fails.
 *
 * @return bool
 */
function auth_external()
{
    return true;
}

/**
 * The username provided by an external authenticatior.
 *
 * @return string|null
 */
function get_external_username()
{
    return auth_sso_get_attr(Config::get('sso.user_attr'), '');
}

/**
 * Return an attribute from the configured attribute store.
 * Returns null if the attribute cannot be found
 *
 * @param string $attr The name of the attribute to find
 * @return string|null
 */
function auth_sso_get_attr($attr, $prefix = 'HTTP_')
{
    // Check attribute originates from a trusted proxy - we check it on every attribute just in case this gets called after initial login
    if (auth_sso_proxy_trusted()) {
        // Short circuit everything if the attribute is non-existant or null
        if (empty($attr)) {
            return null;
        }

        $header_key = $prefix . str_replace('-', '_', strtoupper($attr));

        if (Config::get('sso.mode') === 'header' && array_key_exists($header_key, $_SERVER)) {
            return $_SERVER[$header_key];
        } elseif (Config::get('sso.mode') === 'env' && array_key_exists($attr, $_SERVER)) {
            return $_SERVER[$attr];
        } else {
            return null;
        }
    } else {
        throw new AuthenticationException('$config[\'sso\'][\'trusted_proxies\'] is set, but this connection did not originate from trusted source: ' . $_SERVER['REMOTE_ADDR']);
    }
}

/**
 * Checks to see if the connection originated from a trusted source address stored in the configuration.
 * Returns false if the connection is untrusted, true if the connection is trusted, and true if the trusted sources are not defined.
 *
 * @return bool
 */
function auth_sso_proxy_trusted()
{
    // We assume IP is used - if anyone is using a non-ip transport, support will need to be added
    if (Config::get('sso.trusted_proxies')) {
        try {
            // Where did the HTTP connection originate from?
            if (isset($_SERVER['REMOTE_ADDR'])) {
                // Do not replace this with a call to auth_sso_get_attr
                $source = IP::parse($_SERVER['REMOTE_ADDR']);
            } else {
                return false;
            }

            foreach (Config::get('sso.trusted_proxies') as $value) {
                $proxy = IP::parse($value);

                if ($source->innetwork((string) $proxy)) {
                    // Proxy matches trusted subnet
                    return true;
                }
            }
            // No match, proxy is untrusted
            return false;
        } catch (InvalidIpException $e) {
            // Webserver is talking nonsense (or, IPv10 has been deployed, or maybe something weird like a domain socket is in use?)
            return false;
        }
    }
    // Not enabled, trust everything
    return true;
}

/**
 * Calculate the privilege level to assign to a user based on the configuration and attributes supplied by the external authenticator.
 * Returns an integer if the permission is found, or raises an AuthenticationException if the configuration is not valid.
 *
 * @return integer
 */
function auth_sso_calculate_level()
{
    if (Config::get('sso.group_strategy') === 'attribute') {
        if (Config::get('sso.level_attr')) {
            if (is_numeric(auth_sso_get_attr(Config::get('sso.level_attr')))) {
                return (int) auth_sso_get_attr(Config::get('sso.level_attr'));
            } else {
                throw new AuthenticationException('group assignment by attribute requested, but httpd is not setting the attribute to a number');
            }
        } else {
            throw new AuthenticationException('group assignment by attribute requested, but $config[\'sso\'][\'level_attr\'] not set');
        }
    } elseif (Config::get('sso.group_strategy') === 'map') {
        if (Config::get('sso.group_level_map') && is_array(Config::get('sso.group_level_map')) && Config::get('sso.group_delimiter') && Config::get('sso.group_attr')) {
            return (int) auth_sso_parse_groups();
        } else {
            throw new AuthenticationException('group assignment by level map requested, but $config[\'sso\'][\'group_level_map\'], $config[\'sso\'][\'group_attr\'], or $config[\'sso\'][\'group_delimiter\'] are not set');
        }
    } elseif (Config::get('sso.group_strategy') === 'static') {
        if (Config::get('sso.static_level')) {
            return (int) Config::get('sso.static_level');
        } else {
            throw new AuthenticationException('group assignment by static level was requested, but $config[\'sso\'][\'group_level_map\'] was not set');
        }
    }

    throw new AuthenticationException('$config[\'sso\'][\'group_strategy\'] is not set to one of attribute, map or static - configuration is unsafe');
}

/**
 * Map a user to a permission level based on a table mapping, 0 if no matching group is found.
 *
 * @return integer
 */
function auth_sso_parse_groups()
{
    // Parse a delimited group list
    $groups = explode(Config::get('sso.group_delimiter'), auth_sso_get_attr(Config::get('sso.group_attr')));

    $valid_groups = array();

    // Only consider groups that match the filter expression - this is an optimisation for sites with thousands of groups
    if (Config::get('sso.group_filter')) {
        foreach ($groups as $group) {
            if (preg_match(Config::get('sso.group_filter'), $group)) {
                array_push($valid_groups, $group);
            }
        }

        $groups = $valid_groups;
    }

    $level = 0;

    $config_map = Config::get('sso.group_level_map');

    // Find the highest level the user is entitled to
    foreach ($groups as $value) {
        if (isset($config_map[$value])) {
            $map = $config_map[$value];

            if (is_integer($map) && $level < $map) {
                $level = $map;
            }
        }
    }

    return $level;
}
