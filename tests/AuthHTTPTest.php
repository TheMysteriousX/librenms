<?php
/**
 * AuthHTTP.php
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

// Note that as this test set depends on mres(), it is a DBTestCase even though the database is unused
class AuthHTTPTest extends DBTestCase
{
    // Document the modules current behaviour, so that changes trigger test failures
    public function testCapabilityFunctions() {
        $this->assertNull(init_auth());
        $this->assertFalse(reauthenticate(NULL, NULL));
        $this->assertTrue(passwordscanchange() === 0);
        $this->assertNull(changepassword());
        $this->assertTrue(auth_usermanagement() === 1);
        $this->assertTrue(can_update_users() === 1);
        $this->assertTrue(auth_external());
    }

    public function testOldBehaviourAgainstCurrent() {
        $config['auth_mechanism'] = 'http-auth';
        $users = ['steve',  '   steve', 'steve   ', '   steve   ', '    steve   ', '', 'CAT'];
        $vars = ['REMOTE_USER', 'PHP_AUTH_USER'];

        foreach ($vars as $v) {
            foreach ($users as $u) {
                $_SERVER[$v] = $u;

                // Old Behaviour
                if (isset($_SERVER['REMOTE_USER'])) {
                    $old_username = clean($_SERVER['REMOTE_USER']);
                } elseif (isset($_SERVER['PHP_AUTH_USER']) && $config['auth_mechanism'] === 'http-auth') {
                    $old_username = clean($_SERVER['PHP_AUTH_USER']);
                }

                // Current Behaviour
                if (auth_external()) {
                    $new_username = get_external_username();
                }
                $this->assertTrue($old_username === $new_username);
            }

            unset($_SERVER[$v]);
        }

        unset($config['auth_mechanism']);
    }
}
