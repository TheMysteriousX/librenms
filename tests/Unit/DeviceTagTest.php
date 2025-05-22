<?php

namespace LibreNMS\Tests\Unit;

use App\Models\Device;
use App\Models\DeviceTagKey;
use App\Models\User;
use LibreNMS\Config;
use LibreNMS\Tests\InMemoryDbTestCase;

class DeviceTagTest extends InMemoryDbTestCase
{

    public function test_set_and_get_tags_various_types()
    {
        $device = Device::factory()->create();

        // String tag (default)
        $device->setTag(['owner' => 'alice']);
        $this->assertEquals('alice', $device->getTag('owner'));
        $this->assertEquals(['owner' => 'alice'], $device->getTag());

        // Multiple tags
        $tags = ['owner' => 'bob', 'location' => 'datacenter'];
        $device->setTag($tags);
        $this->assertEquals('bob', $device->getTag('owner'));
        $this->assertEquals('datacenter', $device->getTag('location'));
        $this->assertEquals($tags, $device->getTag());

        // Update tag value
        $device->setTag(['role' => 'router']);
        $device->setTag(['role' => 'switch']);
        $this->assertEquals('switch', $device->getTag('role'));

        // Set tag with valid type (email)
        DeviceTagKey::create(['key' => 'email_tag', 'type' => 'email', 'visible' => true]);
        $device->setTag(['email_tag' => 'user@example.com']);
        $this->assertEquals('user@example.com', $device->getTag('email_tag'));

        // Set tag with integer type
        DeviceTagKey::create(['key' => 'int_tag', 'type' => 'integer', 'visible' => true]);
        $device->setTag(['int_tag' => 123]);
        $this->assertEquals(123, $device->getTag('int_tag'));

        // Set tag with url type
        DeviceTagKey::create(['key' => 'url_tag', 'type' => 'url', 'visible' => true]);
        $device->setTag(['url_tag' => 'https://example.com']);
        $this->assertEquals('https://example.com', $device->getTag('url_tag'));
    }

    public function test_set_tag_invalid_types_throw_exception()
    {
        $device = Device::factory()->create();
        DeviceTagKey::create(['key' => 'email_tag', 'type' => 'email', 'visible' => true]);
        DeviceTagKey::create(['key' => 'int_tag', 'type' => 'integer', 'visible' => true]);
        DeviceTagKey::create(['key' => 'url_tag', 'type' => 'url', 'visible' => true]);
        DeviceTagKey::create(['key' => 'timestamp_tag', 'type' => 'timestamp', 'visible' => true]);

        // Email type
        $this->expectException(\InvalidArgumentException::class);
        $device->setTag(['email_tag' => 'not-an-email']);

        // Integer type
        try {
            $device->setTag(['int_tag' => 'not-an-int']);
            $this->fail('Expected exception for invalid integer');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('int_tag', $e->getMessage());
        }

        // URL type
        try {
            $device->setTag(['url_tag' => 'not-a-url']);
            $this->fail('Expected exception for invalid url');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('url_tag', $e->getMessage());
        }

        // Timestamp type
        try {
            $device->setTag(['timestamp_tag' => 'not-a-timestamp']);
            $this->fail('Expected exception for invalid timestamp');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('timestamp_tag', $e->getMessage());
        }
    }

    public function test_delete_tag_and_invalid_key_handling()
    {
        $device = Device::factory()->create();
        $device->setTag(['foo' => 'bar', 'baz' => 'qux']);
        $device->deleteTag('foo');
        $this->assertNull($device->getTag('foo'));
        $this->assertEquals(['baz' => 'qux'], $device->getTag());

        // Deleting a non-existent key should be a noop
        $device->deleteTag('nonexistent');
        $this->assertTrue(true);
    }

    public function test_get_tag_returns_null_for_missing_key()
    {
        $device = Device::factory()->create();
        $this->assertNull($device->getTag('not_set'));
    }
}
