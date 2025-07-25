<?php

/*
 * LocationTest.php
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
 * @copyright  2021 Tony Murray
 * @author     Tony Murray <murraytony@gmail.com>
 */

namespace LibreNMS\Tests\Unit;

use App\Facades\LibrenmsConfig;
use App\Models\Device;
use App\Models\Location;
use LibreNMS\Interfaces\Geocoder;
use LibreNMS\Tests\TestCase;
use LibreNMS\Util\Dns;
use Mockery\MockInterface;

class LocationTest extends TestCase
{
    public function testCanSetLocation(): void
    {
        $device = Device::factory()->make(); /** @var Device $device */
        $device->setLocation('Where');

        $this->assertEquals($device->location->location, 'Where');
        $this->assertNull($device->location->lat);
        $this->assertNull($device->location->lng);

        $device->setLocation(null);
        $this->assertNull($device->location);
    }

    public function testCanNotSetLocation(): void
    {
        $device = Device::factory()->make(); /** @var Device $device */
        $location = Location::factory()->make(); /** @var Location $location */
        $device->override_sysLocation = true;
        $device->setLocation($location->location);
        $this->assertNull($device->location);
    }

    public function testCanSetEncodedLocation(): void
    {
        LibrenmsConfig::set('geoloc.dns', false);
        $device = Device::factory()->make(); /** @var Device $device */

        // valid coords
        $location = Location::factory()->withCoordinates()->make(); /** @var Location $location */
        $device->setLocation("$location->location [$location->lat,$location->lng]", true);
        $this->assertEquals("$location->location [$location->lat,$location->lng]", $device->location->location);
        $this->assertEquals($location->location, $device->location->display());
        $this->assertEquals($location->lat, $device->location->lat);
        $this->assertEquals($location->lng, $device->location->lng);

        // with space
        $location = Location::factory()->withCoordinates()->make(); /** @var Location $location */
        $device->setLocation("$location->location [$location->lat, $location->lng]", true);
        $this->assertEquals("$location->location [$location->lat, $location->lng]", $device->location->location);
        $this->assertEquals($location->location, $device->location->display());
        $this->assertEquals("$location->location [$location->lat,$location->lng]", $device->location->display(true));
        $this->assertEquals($location->lat, $device->location->lat);
        $this->assertEquals($location->lng, $device->location->lng);

        // invalid coords
        $location = Location::factory()->withCoordinates()->make(['lat' => 251.5007138]); /** @var Location $location */
        $name = "$location->location [$location->lat,$location->lng]";
        $device->setLocation($name, true);
        $this->assertEquals($name, $device->location->location);
        $this->assertEquals($name, $device->location->display());
        $this->assertEquals($name, $device->location->display(true));
        $this->assertNull($device->location->lat);
        $this->assertNull($device->location->lng);
    }

    public function testCanHandleGivenCoordinates(): void
    {
        LibrenmsConfig::set('geoloc.dns', false);
        $device = Device::factory()->make(); /** @var Device $device */
        $location = Location::factory()->withCoordinates()->make(); /** @var Location $location */
        $device->setLocation($location);
        $this->assertEquals($location->location, $device->location->location);
        $this->assertEquals($location->location, $device->location->display());
        $this->assertEquals("$location->location [$location->lat,$location->lng]", $device->location->display(true));
        $this->assertEquals($location->lat, $device->location->lat);
        $this->assertEquals($location->lng, $device->location->lng);
    }

    public function testCanNotSetFixedCoordinates(): void
    {
        $device = Device::factory()->make(); /** @var Device $device */
        $locationOne = Location::factory()->withCoordinates()->make(); /** @var Location $locationOne */
        $locationTwo = Location::factory(['location' => $locationOne->location])->withCoordinates()->make(); /** @var Location $locationTwo */
        $device->setLocation($locationOne);
        $this->assertEquals($locationOne->lat, $device->location->lat);
        $this->assertEquals($locationOne->lng, $device->location->lng);

        $device->location->fixed_coordinates = true;
        $device->setLocation($locationTwo);
        $this->assertEquals($locationOne->lat, $device->location->lat);
        $this->assertEquals($locationOne->lng, $device->location->lng);

        $device->location->fixed_coordinates = false;
        $device->setLocation($locationTwo);
        $this->assertEquals($locationTwo->lat, $device->location->lat);
        $this->assertEquals($locationTwo->lng, $device->location->lng);
    }

    public function testDnsLookup(): void
    {
        $example = 'SW1A2AA.find.me.uk';
        $expected = ['lat' => 51.50354111111111, 'lng' => -0.12766972222222223];

        $this->mock(\Net_DNS2_Resolver::class, function (MockInterface $mock) use ($example, $expected) {
            $loc = new \Net_DNS2_RR_LOC();
            $loc->name = $example;
            $loc->latitude = $expected['lat'];
            $loc->longitude = $expected['lng'];
            $answer = (object) ['answer' => [$loc]];
            $mock->shouldReceive('query')->with($example, 'LOC')->once()->andReturn($answer);
        });

        $result = $this->app->make(Dns::class)->getCoordinates($example);

        $this->assertEquals($expected, $result);
    }

    public function testCanSetDnsCoordinate(): void
    {
        LibrenmsConfig::set('geoloc.dns', true);
        $device = Device::factory()->make(); /** @var Device $device */
        $location = Location::factory()->withCoordinates()->make(); /** @var Location $location */
        $this->mock(Dns::class, function (MockInterface $mock) use ($location) {
            $mock->shouldReceive('getCoordinates')->once()->andReturn($location->only(['lat', 'lng']));
        });

        $device->setLocation($location->location, true);
        $this->assertEquals($location->location, $device->location->location);
        $this->assertEquals($location->lat, $device->location->lat);
        $this->assertEquals($location->lng, $device->location->lng);

        LibrenmsConfig::set('geoloc.dns', false);
        $device->setLocation('No DNS', true);
        $this->assertEquals('No DNS', $device->location->location);
        $this->assertNull($device->location->lat);
        $this->assertNull($device->location->lng);
    }

    public function testCanSetByApi(): void
    {
        $device = Device::factory()->make(); /** @var Device $device */
        $location = Location::factory()->withCoordinates()->make(); /** @var Location $location */
        $this->mock(Geocoder::class, function (MockInterface $mock) use ($location) {
            $mock->shouldReceive('getCoordinates')->once()->andReturn($location->only(['lat', 'lng']));
        });
        // Disable DNS lookup since we're not testing that.
        LibrenmsConfig::set('geoloc.dns', false);

        LibrenmsConfig::set('geoloc.latlng', false);
        $device->setLocation('No API', true);
        $this->assertEquals('No API', $device->location->location);
        $this->assertNull($device->location->lat);
        $this->assertNull($device->location->lng);

        LibrenmsConfig::set('geoloc.latlng', true);
        $device->setLocation('API', true);
        $this->assertEquals('API', $device->location->location);
        $this->assertEquals($location->lat, $device->location->lat);
        $this->assertEquals($location->lng, $device->location->lng);

        // preset coord = skip api
        $device->setLocation('API', true);
        $this->assertEquals($location->lat, $device->location->lat);
        $this->assertEquals($location->lng, $device->location->lng);
    }

    public function testCorrectPrecedence(): void
    {
        $device = Device::factory()->make(); /** @var Device $device */
        $location_encoded = Location::factory()->withCoordinates()->make(); /** @var Location $location_encoded */
        $location_fixed = Location::factory()->withCoordinates()->make(); /** @var Location $location_fixed */
        $location_api = Location::factory()->withCoordinates()->make(); /** @var Location $location_api */
        $location_dns = Location::factory()->withCoordinates()->make(); /** @var Location $location_dns */
        LibrenmsConfig::set('geoloc.dns', true);
        $this->mock(Dns::class, function (MockInterface $mock) use ($location_dns) {
            $mock->shouldReceive('getCoordinates')->times(3)->andReturn(
                $location_dns->only(['lat', 'lng']),
                [],
                []
            );
        });

        LibrenmsConfig::set('geoloc.latlng', true);
        $this->mock(Geocoder::class, function (MockInterface $mock) use ($location_api) {
            $mock->shouldReceive('getCoordinates')->once()->andReturn($location_api->only(['lat', 'lng']));
        });

        // fixed first
        $location_fixed->location = "$location_fixed [-42, 42]"; // encoded should not be used
        $device->setLocation($location_fixed, true);
        $this->assertEquals($location_fixed->lat, $device->location->lat);
        $this->assertEquals($location_fixed->lng, $device->location->lng);

        // then encoded
        $device->setLocation($location_encoded->display(true), true);
        $this->assertEquals($location_encoded->lat, $device->location->lat);
        $this->assertEquals($location_encoded->lng, $device->location->lng);

        // then dns
        $device->setLocation($location_encoded->location, true);
        $this->assertEquals($location_dns->lat, $device->location->lat);
        $this->assertEquals($location_dns->lng, $device->location->lng);

        // then api
        $device->setLocation($location_encoded->location, true);
        $this->assertEquals($location_dns->lat, $device->location->lat);
        $this->assertEquals($location_dns->lng, $device->location->lng);

        $device->location->lat = null; // won't be used if latitude is set
        $device->setLocation($location_encoded->location, true);
        $this->assertEquals($location_api->lat, $device->location->lat);
        $this->assertEquals($location_api->lng, $device->location->lng);
    }
}
