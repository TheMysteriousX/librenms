<?php

namespace App\Console\Commands;

use App\Console\LnmsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputOption;

class DeviceTagsDefine extends LnmsCommand
{
    protected $name = 'device:define-tags';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();

        $this->addArgument('keys', InputArgument::IS_ARRAY | InputArgument::REQUIRED, 'Tag or space separated list of tags to define');
        $this->addOption('type', 't', InputOption::VALUE_OPTIONAL, "Tag type ({implode(', ', \\App\\Models\\DeviceTagKey::\$allowedTypes)})", 'string');
        $this->addOption('visible', null, InputOption::VALUE_OPTIONAL, 'Set tag visibility (true/false)', 'true');
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $keys = $this->argument('keys');
        $type = $this->option('type');
        $visible = filter_var($this->option('visible'), FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);

        if ($visible === null) {
            $this->error("Invalid value for --visible, must be true or false");
            return 2;
        }

        if (empty($keys)) {
            $this->error('No tag key(s) specified for define.');
            return 2;
        }

        $type = $type ?: 'string';
        foreach ($keys as $k) {
            if (!in_array($type, \App\Models\DeviceTagKey::$allowedTypes, true)) {
                $this->error("Invalid type '$type'. Allowed: " . implode(', ', \App\Models\DeviceTagKey::$allowedTypes));
                return 2;
            }
            $tagKey = \App\Models\DeviceTagKey::firstOrCreate(
                ['key' => $k],
                ['type' => $type, 'visible' => $visible]
            );
            $this->info("Defined tag key: $k (type: $type, visible: " . ($visible ? 'true' : 'false') . ")");
        }
        return 0;
    }
}
