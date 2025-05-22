<?php

/**
 * DeviceTagKey.php
 *
 * Model for device tag keys.
 *
 * @copyright 2024
 */

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use LibreNMS\Interfaces\Models\Keyable;

class DeviceTagKey extends Model implements Keyable
{
    protected $table = 'tag_keys';
    protected $primaryKey = 'tag_key_id';
    public $timestamps = false;

    protected $fillable = [
        'key',
        'type',
        'visible',
    ];

    protected $casts = [
        'visible' => 'boolean',
    ];

    public static $allowedTypes = ['string', 'integer', 'email', 'url'];

    /**
     * Get a string that can identify a unique instance of this model
     *
     * @return string|int
     */
    public function getCompositeKey()
    {
        return $this->key;
    }

    /**
     * Relation to DeviceTag
     */
    public function tags()
    {
        return $this->hasMany(DeviceTag::class, 'tag_key_id');
    }

    /**
     * Validate a value against this key's type
     *
     * @param mixed $value
     * @return bool
     */
    public function validateValue($value)
    {
        switch ($this->type) {
            case 'integer':
                return filter_var($value, FILTER_VALIDATE_INT) !== false;
            case 'email':
                return filter_var($value, FILTER_VALIDATE_EMAIL) !== false;
            case 'url':
                return filter_var($value, FILTER_VALIDATE_URL) !== false;
            case 'string':
            default:
                return is_string($value);
        }
    }

    /**
     * Validate the type value for the model
     *
     * @return bool
     */
    public function isValidType()
    {
        return in_array($this->type, self::$allowedTypes, true);
    }

    /**
     * Validate a tag key string
     *
     * @param string $key
     * @return bool
     */
    public static function isValidKey(string $key): bool
    {
        // Allow any Unicode letter, number, underscore, no whitespace, any order
        return preg_match('/^[\p{L}\p{N}_]+$/u', $key) === 1;
    }

    /**
     * Get the key attribute, always lowercased
     *
     * @param string $value
     * @return string
     */
    public function getKeyAttribute($value)
    {
        return mb_strtolower($value, 'UTF-8');
    }

    /**
     * Set the key attribute, always lowercased and validated
     *
     * @param string $value
     * @throws \InvalidArgumentException
     */
    public function setKeyAttribute($value)
    {
        $value = mb_strtolower($value, 'UTF-8');
        if (!self::isValidKey($value)) {
            throw new \InvalidArgumentException('Tag key must start with a letter, contain only letters, numbers, and underscores, have no spaces, and be lowercase. Unicode is allowed.');
        }
        $this->attributes['key'] = $value;
    }
}
