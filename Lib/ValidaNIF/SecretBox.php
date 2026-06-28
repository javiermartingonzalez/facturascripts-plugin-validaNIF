<?php

namespace FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF;

/**
 * Compatibilidad con versiones anteriores del plugin.
 *
 * Desde la versiÃ³n 0.7 se guarda la contraseÃ±a de forma directa en los ajustes,
 * siguiendo un enfoque similar al de otros plugins de FacturaScripts que guardan
 * la contraseÃ±a del certificado en el modelo/configuraciÃ³n correspondiente.
 *
 * Este helper se mantiene para poder leer valores antiguos cifrados con el
 * prefijo gcm: sin romper instalaciones de prueba previas.
 */
final class SecretBox
{
    public static function encrypt(string $plain): string
    {
        return $plain;
    }

    public static function decrypt(string $stored): string
    {
        if ($stored === '') {
            return '';
        }

        if (str_starts_with($stored, 'gcm:') && function_exists('openssl_decrypt')) {
            $plain = self::decryptGcm($stored);
            return $plain !== '' ? $plain : '';
        }

        return $stored;
    }

    private static function decryptGcm(string $encoded): string
    {
        $raw = base64_decode(substr($encoded, 4), true);
        if ($raw === false || strlen($raw) < 28) {
            return '';
        }

        $iv = substr($raw, 0, 12);
        $tag = substr($raw, 12, 16);
        $cipher = substr($raw, 28);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag);
        return $plain === false ? '' : $plain;
    }

    private static function key(): string
    {
        $seed = 'ValidaNIF';
        if (defined('FS_COOKIES_KEY')) {
            $seed .= '|' . FS_COOKIES_KEY;
        }
        if (defined('FS_DB_NAME')) {
            $seed .= '|' . FS_DB_NAME;
        }
        if (defined('FS_FOLDER')) {
            $seed .= '|' . FS_FOLDER;
        }

        return hash('sha256', $seed, true);
    }
}
