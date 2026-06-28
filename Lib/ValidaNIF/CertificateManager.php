<?php

namespace FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF;

use FacturaScripts\Core\Tools;
use RuntimeException;

final class CertificateManager
{
    public const RELATIVE_DIR = 'MyFiles/ValidaNIF';

    private const PEM_FILE = 'certificate.pem';
    private const P12_FILE = 'certificate.p12';
    private const PASSPHRASE_FILE = 'certificate.pass';

    public static function certificatePath(): string
    {
        return self::storageDir() . DIRECTORY_SEPARATOR . self::PEM_FILE;
    }

    public static function originalCertificatePath(): string
    {
        return self::storageDir() . DIRECTORY_SEPARATOR . self::P12_FILE;
    }

    public static function hasCertificate(): bool
    {
        return is_readable(self::certificatePath());
    }

    public static function hasPassphrase(string $storedValue = ''): bool
    {
        return self::readPassphrase($storedValue) !== '';
    }

    public static function readPassphrase(string $storedValue = ''): string
    {
        $storedPassphrase = SecretBox::decrypt($storedValue);
        if ($storedPassphrase !== '') {
            return $storedPassphrase;
        }

        $file = self::passphrasePath();
        if (is_readable($file)) {
            $passphrase = file_get_contents($file);
            return $passphrase === false ? '' : rtrim($passphrase, "\r\n");
        }

        return '';
    }

    public static function savePassphrase(string $passphrase): void
    {
        self::ensureStorageDir();
        $file = self::passphrasePath();
        if (file_put_contents($file, $passphrase) === false) {
            throw new RuntimeException(Tools::trans('certificate-error-save-passphrase'));
        }
        @chmod($file, 0600);
    }

    public static function saveP12(string $tmpPath, string $passphrase): void
    {
        if (!is_readable($tmpPath)) {
            throw new RuntimeException(Tools::trans('certificate-error-read-upload'));
        }

        if ($passphrase === '') {
            throw new RuntimeException(Tools::trans('certificate-error-passphrase-required'));
        }

        $raw = file_get_contents($tmpPath);
        if ($raw === false || $raw === '') {
            throw new RuntimeException(Tools::trans('certificate-error-empty-upload'));
        }

        self::clearOpenSslErrors();

        $certs = [];
        if (openssl_pkcs12_read($raw, $certs, $passphrase)) {
            self::writePemFromPhpCertificates($certs);
            self::writeOriginalCertificate($raw);
            return;
        }

        try {
            self::convertWithOpenSslBinary($tmpPath, $passphrase);
            self::writeOriginalCertificate($raw);
            return;
        } catch (RuntimeException) {
            throw new RuntimeException(Tools::trans('certificate-error-open-p12'));
        }
    }

    public static function deleteCertificate(): void
    {
        foreach ([self::certificatePath(), self::originalCertificatePath(), self::passphrasePath()] as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }
    }

    private static function writePemFromPhpCertificates(array $certs): void
    {
        if (empty($certs['cert']) || empty($certs['pkey'])) {
            throw new RuntimeException(Tools::trans('certificate-error-missing-private-key'));
        }

        $normalize = static function (string $value): string {
            return rtrim(preg_replace("/\r\n?/", "\n", trim($value)) ?? trim($value)) . "\n";
        };

        $pem = $normalize((string)$certs['cert']) . "\n" . $normalize((string)$certs['pkey']);
        if (!empty($certs['extracerts'])) {
            $extraCerts = is_array($certs['extracerts']) ? $certs['extracerts'] : [$certs['extracerts']];
            foreach ($extraCerts as $extraCert) {
                $pem .= "\n" . $normalize((string)$extraCert);
            }
        }

        self::validatePemContent($pem);
        self::writePemAtomically($pem);
    }

    private static function convertWithOpenSslBinary(string $p12Path, string $passphrase): void
    {
        if (!function_exists('proc_open')) {
            throw new RuntimeException(Tools::trans('certificate-error-convert-server'));
        }

        self::ensureStorageDir();

        $tmpDir = self::storageDir();
        $passwordInFile = tempnam($tmpDir, 'validanif-passin-');
        $pemTempFile = tempnam($tmpDir, 'validanif-pem-');
        if ($passwordInFile === false || $pemTempFile === false) {
            throw new RuntimeException(Tools::trans('certificate-error-temp-files'));
        }

        try {
            @chmod($passwordInFile, 0600);
            @chmod($pemTempFile, 0600);

            if (file_put_contents($passwordInFile, $passphrase . PHP_EOL) === false) {
                throw new RuntimeException(Tools::trans('certificate-error-prepare-conversion'));
            }

            $command = [
                self::opensslBinary(),
                'pkcs12',
                '-legacy',
                '-in', $p12Path,
                '-out', $pemTempFile,
                '-passin', 'file:' . $passwordInFile,
                '-nodes',
            ];

            $result = self::runCommand($command);
            if ($result['exitCode'] !== 0) {
                // Reintento sin -legacy para instalaciones con OpenSSL antiguo o sin provider legacy.
                $command = [
                    self::opensslBinary(),
                    'pkcs12',
                    '-in', $p12Path,
                    '-out', $pemTempFile,
                    '-passin', 'file:' . $passwordInFile,
                    '-nodes',
                ];
                $result = self::runCommand($command);
            }

            if ($result['exitCode'] !== 0) {
                throw new RuntimeException(Tools::trans('certificate-error-openssl-convert'));
            }

            $pem = file_get_contents($pemTempFile);
            if ($pem === false || trim($pem) === '') {
                throw new RuntimeException(Tools::trans('certificate-error-openssl-empty-pem'));
            }

            self::validatePemContent($pem);
            self::writePemAtomically($pem);
        } finally {
            foreach ([$passwordInFile, $pemTempFile] as $file) {
                if (is_string($file) && file_exists($file)) {
                    @unlink($file);
                }
            }
        }
    }

    /**
     * @param array<int,string> $command
     * @return array{exitCode:int,stdout:string,stderr:string}
     */
    private static function runCommand(array $command): array
    {
        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = @proc_open($command, $descriptors, $pipes);
        if (!is_resource($process)) {
            throw new RuntimeException(Tools::trans('certificate-error-openssl-exec'));
        }

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);

        return [
            'exitCode' => (int)$exitCode,
            'stdout' => (string)$stdout,
            'stderr' => (string)$stderr,
        ];
    }

    private static function writeOriginalCertificate(string $raw): void
    {
        self::ensureStorageDir();
        $file = self::originalCertificatePath();
        if (file_put_contents($file, $raw) === false) {
            throw new RuntimeException(Tools::trans('certificate-error-save-original'));
        }
        @chmod($file, 0600);
    }

    private static function writePemAtomically(string $pem): void
    {
        self::ensureStorageDir();

        $target = self::certificatePath();
        $tmp = tempnam(self::storageDir(), 'validanif-certificate-');
        if ($tmp === false) {
            throw new RuntimeException(Tools::trans('certificate-error-temp-cert-file'));
        }

        try {
            if (file_put_contents($tmp, $pem) === false) {
                throw new RuntimeException(Tools::trans('certificate-error-save-pem'));
            }

            @chmod($tmp, 0600);
            if (!@rename($tmp, $target)) {
                throw new RuntimeException(Tools::trans('certificate-error-replace-pem'));
            }
            @chmod($target, 0600);
        } finally {
            if (file_exists($tmp)) {
                @unlink($tmp);
            }
        }
    }

    private static function validatePemContent(string $pem): void
    {
        if (strpos($pem, 'BEGIN CERTIFICATE') === false || strpos($pem, 'PRIVATE KEY') === false) {
            throw new RuntimeException(Tools::trans('certificate-error-invalid-pem-content'));
        }

        $x509 = @openssl_x509_read($pem);
        $pkey = @openssl_pkey_get_private($pem);
        if (!$x509 || !$pkey || !@openssl_x509_check_private_key($x509, $pkey)) {
            throw new RuntimeException(Tools::trans('certificate-error-invalid-private-key'));
        }
    }

    private static function opensslBinary(): string
    {
        return PHP_OS_FAMILY === 'Windows' ? 'openssl.exe' : 'openssl';
    }

    private static function passphrasePath(): string
    {
        return self::storageDir() . DIRECTORY_SEPARATOR . self::PASSPHRASE_FILE;
    }

    private static function storageDir(): string
    {
        $base = defined('FS_FOLDER') ? FS_FOLDER : getcwd();
        return $base . DIRECTORY_SEPARATOR . self::RELATIVE_DIR;
    }

    private static function ensureStorageDir(): void
    {
        $dir = self::storageDir();
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException(Tools::trans('certificate-error-storage-dir'));
        }

        @chmod($dir, 0700);
    }

    private static function clearOpenSslErrors(): void
    {
        while (openssl_error_string() !== false) {
        }
    }
}
