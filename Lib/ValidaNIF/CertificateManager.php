<?php

namespace FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF;

use FacturaScripts\Core\Tools;
use RuntimeException;
use Throwable;

final class CertificateManager
{
    public const RELATIVE_DIR = 'MyFiles/ValidaNIF';

    private const PEM_FILE = 'certificate.pem';
    private const P12_FILE = 'certificate.p12';
    private const PASSPHRASE_FILE = 'certificate.pass';
    private const INFO_FILE = 'certificate.info.json';
    private const EXPIRING_SOON_DAYS = 30;

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

    public static function hasPassphrase(): bool
    {
        return self::readPassphrase() !== '';
    }

    public static function readPassphrase(): string
    {
        $file = self::passphrasePath();
        if (false === is_readable($file)) {
            return '';
        }

        $passphrase = file_get_contents($file);
        return $passphrase === false ? '' : rtrim($passphrase, "\r\n");
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

        if (false === self::isBinaryP12($raw)) {
            throw new RuntimeException(Tools::trans('certificate-error-not-binary-p12'));
        }

        self::clearOpenSslErrors();
        $certs = self::readPkcs12($tmpPath, $raw, $passphrase);
        $audit = self::auditCertificates($certs, true);

        if (!empty($audit['errors'])) {
            throw new RuntimeException(implode(' ', $audit['errors']));
        }

        self::writePemFromPhpCertificates($certs);
        self::writeOriginalCertificate($raw);
        self::writeCertificateInfo($audit);
    }

    /**
     * @return array<string,mixed>
     */
    public static function certificateInfo(): array
    {
        $info = self::readCertificateInfo();
        if (!empty($info)) {
            return self::refreshValidityStatus($info);
        }

        $pem = is_readable(self::certificatePath()) ? file_get_contents(self::certificatePath()) : false;
        if ($pem === false || trim($pem) === '') {
            return [];
        }

        $certs = self::certificatesFromPem($pem);
        if (empty($certs['cert'])) {
            return [];
        }

        return self::refreshValidityStatus(self::auditCertificates($certs, false));
    }

    public static function endpointType(): string
    {
        $info = self::certificateInfo();
        return !empty($info['is_seal']) ? 'sello' : 'personal';
    }

    /**
     * Relee el certificado PEM guardado y actualiza la información persistente,
     * incluyendo una nueva comprobación CRL si el certificado publica URLs.
     *
     * @return array<string,mixed>
     */
    public static function refreshCertificateInfo(): array
    {
        $pem = is_readable(self::certificatePath()) ? file_get_contents(self::certificatePath()) : false;
        if ($pem === false || trim($pem) === '') {
            throw new RuntimeException(Tools::trans('certificate-error-no-current-certificate'));
        }

        $certs = self::certificatesFromPem($pem);
        if (empty($certs['cert']) || empty($certs['pkey'])) {
            throw new RuntimeException(Tools::trans('certificate-error-missing-private-key'));
        }

        $audit = self::auditCertificates($certs, true);
        self::writeCertificateInfo($audit);

        return self::refreshValidityStatus(self::persistentCertificateInfo($audit));
    }

    public static function deleteCertificate(): void
    {
        foreach ([self::certificatePath(), self::originalCertificatePath(), self::passphrasePath(), self::infoPath()] as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }
    }

    /**
     * @return array{cert:string,pkey:string,extracerts?:array<int,string>|string}
     */
    private static function readPkcs12(string $tmpPath, string $raw, string $passphrase): array
    {
        $certs = [];
        if (@openssl_pkcs12_read($raw, $certs, $passphrase)) {
            return $certs;
        }

        try {
            $pem = self::convertWithOpenSslBinary($tmpPath, $passphrase);
            $certs = self::certificatesFromPem($pem);
            if (!empty($certs['cert']) && !empty($certs['pkey'])) {
                return $certs;
            }
        } catch (RuntimeException) {
        }

        throw new RuntimeException(Tools::trans('certificate-error-open-p12'));
    }

    /**
     * @return array<string,mixed>
     */
    private static function auditCertificates(array $certs, bool $checkRevocation): array
    {
        $audit = [
            'ok' => false,
            'checked_at_ts' => time(),
            'errors' => [],
            'warnings' => [],
            'subject_cn' => '',
            'issuer_cn' => '',
            'serial_number' => '',
            'valid_from_ts' => 0,
            'valid_to_ts' => 0,
            'is_expired' => false,
            'is_not_valid_yet' => false,
            'is_expiring_soon' => false,
            'days_to_expire' => null,
            'is_qualified' => false,
            'has_signing_capability' => false,
            'has_client_auth_capability' => false,
            'is_seal' => false,
            'is_representative' => false,
            'revocation_status' => 'not_available',
            'revocation_message' => Tools::trans('certificate-revocation-not-checkable'),
            'revocation_urls' => [],
        ];

        if (empty($certs['cert']) || empty($certs['pkey'])) {
            $audit['errors'][] = Tools::trans('certificate-error-missing-private-key');
            return $audit;
        }

        $x509 = @openssl_x509_read((string)$certs['cert']);
        $pkey = @openssl_pkey_get_private((string)$certs['pkey']);
        if (!$x509 || !$pkey || !@openssl_x509_check_private_key($x509, $pkey)) {
            $audit['errors'][] = Tools::trans('certificate-error-invalid-private-key');
            return $audit;
        }

        $certInfo = @openssl_x509_parse((string)$certs['cert']);
        if (false === $certInfo) {
            $audit['errors'][] = Tools::trans('certificate-error-parse');
            return $audit;
        }

        $audit['subject_cn'] = self::firstString($certInfo['subject']['CN'] ?? '');
        $audit['issuer_cn'] = self::firstString($certInfo['issuer']['CN'] ?? '');
        $audit['serial_number'] = self::firstString($certInfo['serialNumberHex'] ?? $certInfo['serialNumber'] ?? '');
        $audit['valid_from_ts'] = (int)($certInfo['validFrom_time_t'] ?? 0);
        $audit['valid_to_ts'] = (int)($certInfo['validTo_time_t'] ?? 0);
        $audit['valid_from_human'] = self::formatTimestamp($audit['valid_from_ts']);
        $audit['valid_to_human'] = self::formatTimestamp($audit['valid_to_ts']);
        $audit['is_qualified'] = self::isQualifiedCertificate($certInfo);
        $audit['has_signing_capability'] = self::hasSigningCapability($certInfo);
        $audit['has_client_auth_capability'] = self::hasClientAuthCapability($certInfo);
        $audit['is_seal'] = self::isSealCertificate($certInfo);
        $audit['is_representative'] = self::isRepresentativeCertificate($certInfo);

        $now = time();
        if ($audit['valid_to_ts'] > 0) {
            $audit['days_to_expire'] = (int)ceil(($audit['valid_to_ts'] - $now) / 86400);
        }

        if ($audit['valid_from_ts'] > 0 && $now < $audit['valid_from_ts']) {
            $audit['is_not_valid_yet'] = true;
            $audit['errors'][] = Tools::trans('certificate-error-not-valid-yet', ['%date%' => $audit['valid_from_human']]);
        }

        if ($audit['valid_to_ts'] > 0 && $now > $audit['valid_to_ts']) {
            $audit['is_expired'] = true;
            $audit['errors'][] = Tools::trans('certificate-error-expired', ['%date%' => $audit['valid_to_human']]);
        } elseif ($audit['valid_to_ts'] > 0 && $audit['days_to_expire'] !== null && $audit['days_to_expire'] <= self::EXPIRING_SOON_DAYS) {
            $audit['is_expiring_soon'] = true;
        }

        if (false === $audit['is_qualified']) {
            $audit['warnings'][] = Tools::trans('certificate-warning-not-qualified');
        }

        if (false === $audit['has_signing_capability']) {
            $audit['warnings'][] = Tools::trans('certificate-error-no-signing-capability');
        }

        if (false === $audit['has_client_auth_capability']) {
            $audit['warnings'][] = Tools::trans('certificate-error-no-client-auth');
        }

        if ($checkRevocation) {
            $revocation = self::checkRevocation($certInfo);
            $audit['revocation_status'] = $revocation['status'];
            $audit['revocation_message'] = $revocation['message'];
            $audit['revocation_urls'] = $revocation['urls'] ?? [];

            if ($revocation['status'] === 'revoked') {
                $audit['errors'][] = Tools::trans('certificate-error-revoked');
            } elseif ($revocation['status'] !== 'ok') {
                $audit['warnings'][] = Tools::trans('certificate-warning-revocation-unknown');
            }
        }

        $audit['ok'] = empty($audit['errors']);
        return $audit;
    }

    /**
     * @return array{status:string,message:string,urls:array<int,string>}
     */
    private static function checkRevocation(array $certInfo): array
    {
        $crlDp = (string)($certInfo['extensions']['crlDistributionPoints'] ?? '');
        if ($crlDp === '' || false === preg_match_all('#https?://[^,\s)]+#i', $crlDp, $matches)) {
            return [
                'status' => 'not_available',
                'message' => Tools::trans('certificate-revocation-not-checkable'),
                'urls' => [],
            ];
        }

        $urls = array_values(array_unique(array_map('trim', $matches[0])));
        $serial = (string)($certInfo['serialNumberHex'] ?? $certInfo['serialNumber'] ?? '');
        foreach ($urls as $crlUrl) {
            try {
                $context = stream_context_create([
                    'http' => ['timeout' => 8],
                    'ssl' => [
                        'verify_peer' => true,
                        'verify_peer_name' => true,
                    ],
                ]);
                $crl = @file_get_contents($crlUrl, false, $context);
                if ($crl === false || $crl === '') {
                    continue;
                }

                if (self::crlContainsSerial($crl, $serial)) {
                    return [
                        'status' => 'revoked',
                        'message' => Tools::trans('certificate-revocation-revoked'),
                        'urls' => $urls,
                    ];
                }

                return [
                    'status' => 'ok',
                    'message' => Tools::trans('certificate-revocation-ok'),
                    'urls' => $urls,
                ];
            } catch (Throwable) {
            }
        }

        return [
            'status' => 'unknown',
            'message' => Tools::trans('certificate-revocation-unknown'),
            'urls' => $urls,
        ];
    }

    private static function crlContainsSerial(string $crlContent, string $serial): bool
    {
        $serialNorm = self::normalizeSerial($serial);
        if ($serialNorm === '') {
            return false;
        }

        foreach ([['-inform', 'DER'], ['-inform', 'PEM'], []] as $formatArgs) {
            $text = self::crlText($crlContent, $formatArgs);
            if ($text === '') {
                continue;
            }

            if (preg_match_all('/Serial Number:\s*([0-9A-F:\s]+)/i', $text, $matches)) {
                foreach ($matches[1] as $listedSerial) {
                    if (self::normalizeSerial((string)$listedSerial) === $serialNorm) {
                        return true;
                    }
                }
            }

            if (str_contains(self::normalizeSerial($text), $serialNorm)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<int,string> $formatArgs
     */
    private static function crlText(string $crlContent, array $formatArgs): string
    {
        if (!function_exists('proc_open')) {
            return '';
        }

        $tmp = tempnam(sys_get_temp_dir(), 'validanif-crl-');
        if ($tmp === false) {
            return '';
        }

        try {
            if (file_put_contents($tmp, $crlContent) === false) {
                return '';
            }

            $command = array_merge([self::opensslBinary(), 'crl'], $formatArgs, ['-in', $tmp, '-noout', '-text']);
            $result = self::runCommand($command);
            return $result['exitCode'] === 0 ? $result['stdout'] : '';
        } finally {
            if (file_exists($tmp)) {
                @unlink($tmp);
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

    private static function convertWithOpenSslBinary(string $p12Path, string $passphrase): string
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
            return $pem;
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

    private static function writeCertificateInfo(array $audit): void
    {
        self::ensureStorageDir();

        $json = json_encode(self::persistentCertificateInfo($audit), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        if ($json === false || file_put_contents(self::infoPath(), $json) === false) {
            return;
        }

        @chmod(self::infoPath(), 0600);
    }

    /**
     * @param array<string,mixed> $audit
     * @return array<string,mixed>
     */
    private static function persistentCertificateInfo(array $audit): array
    {
        foreach ([
            'checked_at',
            'checked_at_human',
            'valid_from',
            'valid_to',
            'valid_from_human',
            'valid_to_human',
            'is_expired',
            'is_not_valid_yet',
            'is_expiring_soon',
            'days_to_expire',
        ] as $runtimeKey) {
            unset($audit[$runtimeKey]);
        }

        return $audit;
    }

    /**
     * @return array<string,mixed>
     */
    private static function readCertificateInfo(): array
    {
        $file = self::infoPath();
        if (false === is_readable($file)) {
            return [];
        }

        $content = file_get_contents($file);
        if ($content === false || trim($content) === '') {
            return [];
        }

        $data = json_decode($content, true);
        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string,mixed> $info
     * @return array<string,mixed>
     */
    private static function refreshValidityStatus(array $info): array
    {
        $info['errors'] = is_array($info['errors'] ?? null) ? $info['errors'] : [];
        $info['warnings'] = is_array($info['warnings'] ?? null) ? $info['warnings'] : [];

        $checkedAt = (int)($info['checked_at_ts'] ?? 0);
        if ($checkedAt <= 0 && !empty($info['checked_at'])) {
            $legacyCheckedAt = strtotime((string)$info['checked_at']);
            $checkedAt = $legacyCheckedAt === false ? 0 : (int)$legacyCheckedAt;
        }

        $info['checked_at_human'] = self::formatTimestamp($checkedAt);

        $now = time();
        $validFrom = (int)($info['valid_from_ts'] ?? 0);
        $validTo = (int)($info['valid_to_ts'] ?? 0);

        $info['valid_from_human'] = self::formatTimestamp($validFrom);
        $info['valid_to_human'] = self::formatTimestamp($validTo);
        $info['days_to_expire'] = $validTo > 0 ? (int)ceil(($validTo - $now) / 86400) : null;
        $info['is_not_valid_yet'] = $validFrom > 0 && $now < $validFrom;
        $info['is_expired'] = $validTo > 0 && $now > $validTo;
        $info['is_expiring_soon'] = false === $info['is_expired']
            && $validTo > 0
            && $info['days_to_expire'] !== null
            && $info['days_to_expire'] <= self::EXPIRING_SOON_DAYS;

        if ($info['is_not_valid_yet']) {
            $message = Tools::trans('certificate-error-not-valid-yet', ['%date%' => $info['valid_from_human']]);
            if (!in_array($message, $info['errors'], true)) {
                $info['errors'][] = $message;
            }
        }

        if ($info['is_expired']) {
            $message = Tools::trans('certificate-error-expired', ['%date%' => $info['valid_to_human']]);
            if (!in_array($message, $info['errors'], true)) {
                $info['errors'][] = $message;
            }
        } elseif ($info['is_expiring_soon']) {
            $message = Tools::trans('certificate-warning-expiring-soon', [
                '%days%' => (string)max(0, (int)$info['days_to_expire']),
                '%date%' => $info['valid_to_human'],
            ]);
            if (!in_array($message, $info['warnings'], true)) {
                $info['warnings'][] = $message;
            }
        }

        $info['ok'] = empty($info['errors']);
        return $info;
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

    /**
     * @return array{cert:string,pkey:string,extracerts?:array<int,string>}
     */
    private static function certificatesFromPem(string $pem): array
    {
        preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $pem, $certMatches);
        preg_match('/-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----.*?-----END (?:[A-Z ]+)?PRIVATE KEY-----/s', $pem, $keyMatch);

        $certificates = $certMatches[0] ?? [];
        return [
            'cert' => $certificates[0] ?? '',
            'pkey' => $keyMatch[0] ?? '',
            'extracerts' => array_slice($certificates, 1),
        ];
    }

    private static function isBinaryP12(string $certContent): bool
    {
        if (str_contains($certContent, '-----BEGIN')) {
            return false;
        }

        $bytes = unpack('C*', substr($certContent, 0, 2));
        if (empty($bytes) || !isset($bytes[1], $bytes[2])) {
            return false;
        }

        return $bytes[1] === 0x30 && in_array($bytes[2], [0x80, 0x81, 0x82, 0x83, 0x84, 0x86], true);
    }

    private static function isQualifiedCertificate(array $certInfo): bool
    {
        $policies = (string)($certInfo['extensions']['certificatePolicies'] ?? '');
        if ($policies === '') {
            return false;
        }

        foreach ([
            '0.4.0.1862.1.1',
            '0.4.0.1862.1.4',
            '0.4.0.1862.1.5',
            '0.4.0.194112.1.0',
            '2.16.724.1.2.2.2.4',
            '2.16.724.1.2.2.2.5',
        ] as $oid) {
            if (str_contains($policies, $oid)) {
                return true;
            }
        }

        return false;
    }

    private static function hasSigningCapability(array $certInfo): bool
    {
        $keyUsage = strtoupper((string)($certInfo['extensions']['keyUsage'] ?? ''));
        if ($keyUsage === '') {
            return true;
        }

        return str_contains($keyUsage, 'DIGITAL SIGNATURE') || str_contains($keyUsage, 'NON REPUDIATION');
    }

    private static function hasClientAuthCapability(array $certInfo): bool
    {
        $eku = strtoupper((string)($certInfo['extensions']['extendedKeyUsage'] ?? ''));
        if ($eku !== '' && (
            str_contains($eku, 'TLS WEB CLIENT AUTHENTICATION')
            || str_contains($eku, 'CLIENT AUTH')
            || str_contains($eku, '1.3.6.1.5.5.7.3.2')
        )) {
            return true;
        }

        $policies = (string)($certInfo['extensions']['certificatePolicies'] ?? '');
        foreach (['1.3.6.1.4.1.18332.5.1.1.1', '1.3.6.1.4.1.5734.3.4', '0.4.0.194112.1.2'] as $oid) {
            if (str_contains($policies, $oid)) {
                return true;
            }
        }

        return $eku === '';
    }

    private static function isSealCertificate(array $certInfo): bool
    {
        $policies = (string)($certInfo['extensions']['certificatePolicies'] ?? '');
        foreach (['0.4.0.1862.1.4', '0.4.0.1862.1.5', '1.3.6.1.4.1.5734.3.5'] as $oid) {
            if (str_contains($policies, $oid)) {
                return true;
            }
        }

        $text = strtoupper(implode(' ', [
            self::firstString($certInfo['subject']['CN'] ?? ''),
            self::firstString($certInfo['subject']['OU'] ?? ''),
            self::firstString($certInfo['subject']['O'] ?? ''),
            self::firstString($certInfo['subject']['description'] ?? ''),
            (string)($certInfo['extensions']['subjectAltName'] ?? ''),
        ]));

        return str_contains($text, 'SELLO ELECTRONICO')
            || str_contains($text, 'SELLO ELECTRÓNICO')
            || str_contains($text, 'ELECTRONIC SEAL');
    }

    private static function isRepresentativeCertificate(array $certInfo): bool
    {
        $subjectString = strtoupper(implode(' ', [
            self::firstString($certInfo['subject']['CN'] ?? ''),
            self::firstString($certInfo['subject']['serialNumber'] ?? ''),
            self::firstString($certInfo['subject']['O'] ?? ''),
            self::firstString($certInfo['subject']['OU'] ?? ''),
            self::firstString($certInfo['subject']['description'] ?? ''),
        ]));

        foreach (['R:', 'REP:', 'REPRESENTANTE:', 'REPRESENTANT:', 'REPRESENTANTE=', 'AGENT ID:'] as $needle) {
            if (str_contains($subjectString, $needle)) {
                return true;
            }
        }

        return false;
    }

    private static function firstString(mixed $value): string
    {
        if (is_array($value)) {
            $value = reset($value);
        }

        return trim((string)$value);
    }

    private static function formatTimestamp(int $timestamp): string
    {
        return $timestamp > 0 ? date('d/m/Y H:i', $timestamp) : '';
    }


    private static function normalizeSerial(string $value): string
    {
        return strtoupper(preg_replace('/[^A-F0-9]/i', '', $value) ?? '');
    }

    private static function opensslBinary(): string
    {
        return PHP_OS_FAMILY === 'Windows' ? 'openssl.exe' : 'openssl';
    }

    private static function passphrasePath(): string
    {
        return self::storageDir() . DIRECTORY_SEPARATOR . self::PASSPHRASE_FILE;
    }

    private static function infoPath(): string
    {
        return self::storageDir() . DIRECTORY_SEPARATOR . self::INFO_FILE;
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
