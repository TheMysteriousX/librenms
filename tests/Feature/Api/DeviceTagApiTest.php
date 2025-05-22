<?php

namespace Tests\Feature\Api;

use App\Models\Device;
use App\Models\DeviceTagKey;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DeviceTagApiTest extends TestCase
{
    use RefreshDatabase;

    protected function actingAsAdmin()
    {
        $user = User::factory()->admin()->create();
        $this->actingAs($user);
    }

    public function test_set_and_get_tag_via_api()
    {
        $device = Device::factory()->create(['hostname' => 'apitest1']);
        $this->actingAsAdmin();

        // Set tags (visible true)
        $response = $this->postJson("/api/v0/devices/{$device->hostname}/tags", [
            'tags' => ['apiowner' => 'bob', 'apilocation' => 'rack1'],
            'visible' => true,
        ]);
        $response->assertStatus(200)
            ->assertJsonFragment(['apiowner' => 'bob', 'apilocation' => 'rack1']);

        // Get all tags
        $response = $this->getJson("/api/v0/devices/{$device->hostname}/tags");
        $response->assertStatus(200)
            ->assertJsonFragment(['apiowner' => 'bob', 'apilocation' => 'rack1']);

        // Get single tag
        $response = $this->getJson("/api/v0/devices/{$device->hostname}/tags/apiowner");
        $response->assertStatus(200)
            ->assertJsonFragment(['apiowner' => 'bob']);

        // Set a hidden tag (visible false)
        $response = $this->postJson("/api/v0/devices/{$device->hostname}/tags", [
            'tags' => ['hiddenapi' => 'secret'],
            'visible' => false,
        ]);
        $response->assertStatus(200)
            ->assertJsonFragment(['hiddenapi' => 'secret']);

        // Confirm tag is set and visible is false
        $tagKey = DeviceTagKey::where('key', 'hiddenapi')->first();
        $this->assertNotNull($tagKey);
        $this->assertFalse($tagKey->visible);

        // Delete tag
        $response = $this->deleteJson("/api/v0/devices/{$device->hostname}/tags/apiowner");
        $response->assertStatus(200);

        // Confirm deletion
        $response = $this->getJson("/api/v0/devices/{$device->hostname}/tags");
        $response->assertStatus(200)
            ->assertJsonMissing(['apiowner' => 'bob']);
    }

    public function test_set_tag_invalid_type_returns_422()
    {
        $device = Device::factory()->create(['hostname' => 'apitest2']);
        $this->actingAsAdmin();
        DeviceTagKey::create(['key' => 'email_tag', 'type' => 'email', 'visible' => true]);
        $response = $this->postJson("/api/v0/devices/{$device->hostname}/tags", [
            'tags' => ['email_tag' => 'not-an-email'],
        ]);
        $response->assertStatus(422);
    }
}
