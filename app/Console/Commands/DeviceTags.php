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
    protected $name = 'device:tags';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();

        $this->addArgument('action', InputArgument::REQUIRED, 'Action to perform (get, set, delete,)', null, ['get', 'set', 'delete']);
        $this->addArgument('device_id', InputArgument::REQUIRED);
        $this->addArgument('tags', InputArgument::IS_ARRAY | InputArgument::OPTIONAL, 'List of space seperated tags (key1=value key2=value) for set operations\nlist of keys for get or delete operations (key1 key2)');
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $device_id = $this->argument('device_id');
        $action = $this->argument('action');
        $tags = $this->argument('tags');
        $key = $this->option('key');
        $type = $this->option('type');

        $device = Device::find($device_id);
        if (! $device) {
            $this->error("Device not found: $device_id");
            return 1;
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
            } catch (\InvalidArgumentException $e) {
                $this->error($e->getMessage());
                return 2;
            }
            $this->info('Tags set.');
            return 0;
        }

        if ($action === 'get') {
            if ($key) {
                $value = $device->getTag($key);
                $this->line($value === null ? "(not set)" : "$key=$value");
            } else {
                $all = $device->getTag();
                foreach ($all as $k => $v) {
                    $this->line("$k=$v");
                }
            }
            return 0;
        }

        if ($action === 'delete') {
            $keys = $tags ?: ($key ? [$key] : []);
            if (empty($keys)) {
                $this->error('No tag key(s) specified for delete.');
                return 2;
            }
            foreach ($keys as $k) {
                $device->deleteTag($k);
                $this->info("Deleted tag: $k");
            }
            return 0;
        }

        $this->error("Unknown action: $action (expected get, set, or delete)");
        return 2;
    }
}
