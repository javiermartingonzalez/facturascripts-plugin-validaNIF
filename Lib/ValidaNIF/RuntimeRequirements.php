<?php

namespace FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF;

use FacturaScripts\Core\Tools;

final class RuntimeRequirements
{
    /**
     * @return array<int,array{label:string,ok:bool,required:bool,message:string}>
     */
    public static function all(): array
    {
        return [
            [
                'label' => Tools::trans('validanif-requirement-openssl-label'),
                'ok' => extension_loaded('openssl'),
                'required' => true,
                'message' => Tools::trans('validanif-requirement-openssl-message'),
            ],
            [
                'label' => Tools::trans('validanif-requirement-soap-label'),
                'ok' => class_exists('SoapClient'),
                'required' => true,
                'message' => Tools::trans('validanif-requirement-soap-message'),
            ],
            [
                'label' => Tools::trans('validanif-requirement-dom-label'),
                'ok' => class_exists('DOMDocument'),
                'required' => true,
                'message' => Tools::trans('validanif-requirement-dom-message'),
            ],
            [
                'label' => Tools::trans('validanif-requirement-myfiles-label'),
                'ok' => self::canUseStorage(),
                'required' => true,
                'message' => Tools::trans('validanif-requirement-myfiles-message'),
            ],
        ];
    }

    /**
     * @param array<int,array{label:string,ok:bool,required:bool,message:string}> $requirements
     */
    public static function isOk(array $requirements): bool
    {
        foreach ($requirements as $requirement) {
            if (($requirement['required'] ?? false) && false === ($requirement['ok'] ?? false)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<int,array{label:string,ok:bool,required:bool,message:string}> $requirements
     * @return array<int,string>
     */
    public static function blockingErrors(array $requirements): array
    {
        $errors = [];
        foreach ($requirements as $requirement) {
            if (($requirement['required'] ?? false) && false === ($requirement['ok'] ?? false)) {
                $errors[] = Tools::trans('validanif-missing-required', [
                    '%requirement%' => $requirement['label'] ?? Tools::trans('validanif-server-requirements'),
                ]);
            }
        }

        return $errors;
    }

    private static function canUseStorage(): bool
    {
        $base = defined('FS_FOLDER') ? FS_FOLDER : getcwd();
        $myFiles = $base . DIRECTORY_SEPARATOR . 'MyFiles';
        $target = $myFiles . DIRECTORY_SEPARATOR . 'ValidaNIF';

        if (is_dir($target)) {
            return is_writable($target);
        }

        if (is_dir($myFiles)) {
            return is_writable($myFiles);
        }

        return is_writable($base);
    }

}
