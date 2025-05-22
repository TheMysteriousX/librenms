<?php

namespace Tests\Unit;

use App\Models\Device;
use App\Models\DeviceTagKey;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DeviceTagTest extends TestCase
{
    use RefreshDatabase;

    public function test_set_and_get_single_tag()
    {
        $device = Device::factory()->create();
        $device->setTag(['owner' => 'alice']);
        $this->assertEquals('alice', $device->getTag('owner'));
        $this->assertEquals(['owner' => 'alice'], $device->getTag());
    }

    public function test_set_and_get_multiple_tags()
    {
        $device = Device::factory()->create();
        $tags = ['owner' => 'bob', 'location' => 'datacenter'];
        $device->setTag($tags);
        $this->assertEquals('bob', $device->getTag('owner'));
        $this->assertEquals('datacenter', $device->getTag('location'));
        $this->assertEquals($tags, $device->getTag());
    }

    public function test_update_tag_value()
    {
        $device = Device::factory()->create();
        $device->setTag(['role' => 'router']);
        $device->setTag(['role' => 'switch']);
        $this->assertEquals('switch', $device->getTag('role'));
    }

    public function test_delete_tag()
    {
        $device = Device::factory()->create();
        $device->setTag(['foo' => 'bar', 'baz' => 'qux']);
        $device->deleteTag('foo');
        $this->assertNull($device->getTag('foo'));
        $this->assertEquals(['baz' => 'qux'], $device->getTag());
    }

    public function test_get_tag_returns_null_for_missing_key()
    {
        $device = Device::factory()->create();
        $this->assertNull($device->getTag('not_set'));
    }

    public function test_set_tag_with_visible_false()
    {
        $device = Device::factory()->create();
        $device->setTag(['hidden_tag' => 'secret'], false);
        $this->assertEquals('secret', $device->getTag('hidden_tag'));
        $tagKey = DeviceTagKey::where('key', 'hidden_tag')->first();
        $this->assertFalse($tagKey->visible);
    }

    public function test_set_tag_invalid_type_throws_exception()
    {
        $device = Device::factory()->create();
        DeviceTagKey::create(['key' => 'email_tag', 'type' => 'email', 'visible' => true]);
        $this->expectException(\InvalidArgumentException::class);
        $device->setTag(['email_tag' => 'not-an-email']);
    }

    public function test_set_tag_valid_type_succeeds()
    {
        $device = Device::factory()->create();
        DeviceTagKey::create(['key' => 'email_tag', 'type' => 'email', 'visible' => true]);
        $device->setTag(['email_tag' => 'user@example.com']);
        $this->assertEquals('user@example.com', $device->getTag('email_tag'));
    }

    public function test_delete_tag_invalid_key_does_not_throw()
    {
        $device = Device::factory()->create();
        $device->deleteTag('nonexistent');
        $this->assertTrue(true); // Should not throw
    }
}
