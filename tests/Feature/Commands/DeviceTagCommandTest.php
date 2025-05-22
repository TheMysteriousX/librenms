<?php

namespace Tests\Feature\Console;

use App\Models\Device;
use App\Models\DeviceTagKey;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class DeviceTagCommandTest extends TestCase
{
    use RefreshDatabase;

    public function test_cli_set_get_delete_tag()
    {
        $device = Device::factory()->create();

        // Set tag (visible true)
        $this->artisan('device:tags', [
            'action' => 'set',
            'device_id' => $device->device_id,
            'tags' => ['cliowner=carol'],
            '--visible' => 'true',
        ])->assertExitCode(0);

        // Get tag
        $this->artisan('device:tags', [
            'action' => 'get',
            'device_id' => $device->device_id,
            '--key' => 'cliowner',
        ])->expectsOutput('cliowner=carol')->assertExitCode(0);

        // Set tag (visible false)
        $this->artisan('device:tags', [
            'action' => 'set',
            'device_id' => $device->device_id,
            'tags' => ['hiddencli=secret'],
            '--visible' => 'false',
        ])->assertExitCode(0);

        $tagKey = DeviceTagKey::where('key', 'hiddencli')->first();
        $this->assertNotNull($tagKey);
        $this->assertFalse($tagKey->visible);

        // Delete tag
        $this->artisan('device:tags', [
            'action' => 'delete',
            'device_id' => $device->device_id,
            'tags' => ['cliowner'],
        ])->assertExitCode(0);

        // Get tag after delete
        $this->artisan('device:tags', [
            'action' => 'get',
            'device_id' => $device->device_id,
            '--key' => 'cliowner',
        ])->expectsOutput('(not set)')->assertExitCode(0);
    }

    public function test_cli_set_tag_invalid_type_fails()
    {
        $device = Device::factory()->create();
        DeviceTagKey::create(['key' => 'email_tag', 'type' => 'email', 'visible' => true]);
        $this->artisan('device:tags', [
            'action' => 'set',
            'device_id' => $device->device_id,
            'tags' => ['email_tag=not-an-email'],
        ])->expectsOutputToContain('does not match type')->assertExitCode(2);
    }
}
