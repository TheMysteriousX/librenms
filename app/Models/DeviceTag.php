<?php

namespace App\Console\Commands;

use App\Console\LnmsCommand;
use App\Models\Device;
use App\Models\DeviceTag;
use Illuminate\Support\Arr;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;

class DeviceTags extends LnmsCommand
{
    /**
     * The name of the console command.
     *
     * @var string
     */
    protected $name = 'device:tags';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();

        $this->addArgument('action', InputArgument::REQUIRED, 'Action to perform (get, set, delete, define)', null, ['get', 'set', 'delete', 'define']);
        $this->addArgument('device', InputArgument::REQUIRED, 'Device ID to act on');
        $this->addArgument('tags', InputArgument::IS_ARRAY | InputArgument::OPTIONAL, 'List of key=value or keys');
        $this->addOption('type', 't', InputOption::VALUE_OPTIONAL, 'Tag type for define (string, integer, email)');
        $this->addOption('visible', null, InputOption::VALUE_OPTIONAL, 'Set tag visibility (true/false)', 'true');
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $device_id = $this->argument('device');
        $action = $this->argument('action');
        $tags = $this->argument('tags');
        $type = $this->option('type');

        $device = Device::find($device_id);
        if (! $device) {
            $this->error("Device not found: $device_id");
            return 1;
        }

        if ($action === 'define') {
            // Define tag key(s) with type
            $visible = filter_var($this->option('visible'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
            if ($visible === null) {
                $this->error("Invalid value for --visible, must be true or false");
                return 2;
            }
            $to_define = $tags ?: ($key ? [$key] : []);
            if (empty($to_define)) {
                $this->error('No tag key(s) specified for define.');
                return 2;
            }
            $type = $type ?: 'string';
            foreach ($to_define as $k) {
                if (!in_array($type, \App\Models\DeviceTagKey::$allowedTypes, true)) {
                    $this->error("Invalid type '$type'. Allowed: " . implode(', ', \App\Models\DeviceTagKey::$allowedTypes));
                    return 2;
                }
                $tagKey = \App\Models\DeviceTagKey::updateOrCreate(
                    ['key' => $k],
                    ['type' => $type, 'visible' => $visible]
                );
                $this->info("Defined tag key: $k (type: $type, visible: " . ($visible ? 'true' : 'false') . ")");
            }
            return 0;
        }

        if ($action === 'set') {
            $pairs = [];
            foreach ($tags as $tag) {
                if (strpos($tag, '=') === false) {
                    $this->error("Invalid tag format: $tag (expected key=value)");
                    return 2;
                }
                [$k, $v] = explode('=', $tag, 2);
                $pairs[$k] = $v;
            }
            try {
                $device->setTag($pairs);

                foreach ($pairs as $k => $v) {
                    $this->line("$k=$v");
                }
            } catch (\InvalidArgumentException $e) {
                $this->error($e->getMessage());
                return 2;
            }
            return 0;
        }

        if ($action === 'get') {
            if ($tags) {
                foreach ($tags as $tag) {
                    $value = $device->getTag($tag);
                    if ($value !== null) {
                        $this->line("$tag=$value");
                    }
                }
            } else {
                $all = $device->getTag();
                foreach ($all as $k => $v) {
                    $this->line("$k=$v");
                }
            }
            return 0;
        }

        if ($action === 'delete') {
            foreach ($tags as $k) {
                $device->deleteTag($k);
                $this->info("Deleted tag: $k");
            }
            return 0;
        }

        $this->error("Unknown action: $action (expected get, set, delete, define)");
        return 2;
    }
}
