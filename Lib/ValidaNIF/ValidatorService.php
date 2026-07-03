<?php

namespace FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF;

use FacturaScripts\Core\Tools;
use Throwable;

final class ValidatorService
{
    public const APP_SETTINGS = 'validanif';
    public const CERT_SETTINGS = 'validanif_cert';
    private const DIAGNOSTIC_TEXT_LIMIT = 10000;

    /**
     * @return array{ok:bool,result?:array{nif:string,nombre:string,nombre_aeat:string,resultado:string},error?:string,technical_error?:string,category?:string,reference?:string}
     */
    public function validateParty(
        string $tipo,
        string $codigo,
        string $nif,
        string $nombre,
        string $usuario = ''
    ): array {
        try {
            $client = $this->client();
            $result = $client->validateOne($nif, $nombre);
            $isIdentified = self::isIdentified($result['resultado']);

            if (!$isIdentified) {
                return [
                    'ok' => false,
                    'result' => $result,
                    'error' => $result['resultado'],
                    'category' => 'aeat-result',
                ];
            }

            return ['ok' => true, 'result' => $result];
        } catch (Throwable $exception) {
            $technicalError = $exception->getMessage();
            $category = self::categorizeError($technicalError);
            $reference = self::newDiagnosticId();
            $diagnosticContext = isset($client) ? $client->getDiagnosticContext() : [];
            $errorContext = [
                'reference' => $reference,
                'tipo' => $tipo,
                'codigo' => $codigo,
                'usuario' => $usuario,
                'nif' => $nif,
                'endpoint_type' => $this->endpointType(),
                'category' => $category,
                'technical_error' => $technicalError,
                'context' => $diagnosticContext,
            ];

            if (isset($client)) {
                $errorContext['transport'] = $client->getLastTransport();
                $errorContext['soap_request'] = self::shorten($client->getLastRequest());
                $errorContext['soap_response'] = self::shorten($client->getLastResponse());
            }

            $isCertificateIssue = in_array($category, ['certificate', 'certificate-passphrase'], true);
            $debugDetail = json_encode($errorContext, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

            if (false === $isCertificateIssue) {
                Tools::log()->error(Tools::trans('technical-diagnostic', [
                    '%reference%' => $reference,
                    '%detail%' => json_encode($errorContext, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                ]));
            }

            return [
                'ok' => false,
                'error' => self::friendlyError($category, $technicalError),
                'technical_error' => $technicalError,
                'category' => $category,
                'reference' => $isCertificateIssue ? '' : $reference,
                'debug_detail' => $isCertificateIssue ? '' : ($debugDetail === false ? $technicalError : $debugDetail),
            ];
        }
    }

    public static function errorDiagnostic(
        string $tipo,
        string $codigo,
        string $category,
        string $technicalError,
        array $context = []
    ): string {
        $reference = self::newDiagnosticId();
        $errorContext = [
            'reference' => $reference,
            'tipo' => $tipo,
            'codigo' => $codigo,
            'category' => $category,
            'technical_error' => $technicalError,
            'context' => $context,
        ];

        Tools::log()->error(Tools::trans('technical-diagnostic', [
            '%reference%' => $reference,
            '%detail%' => json_encode($errorContext, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
        ]));

        return $reference;
    }

    private function client(): AeatNifClient
    {
        $passphrase = CertificateManager::readPassphrase();
        $endpointType = $this->endpointType();
        $timeout = (int)Tools::settings(self::APP_SETTINGS, 'timeout', 30);

        return new AeatNifClient(
            CertificateManager::certificatePath(),
            $passphrase,
            AeatNifClient::endpointFromType($endpointType),
            max(5, $timeout)
        );
    }

    private function endpointType(): string
    {
        return CertificateManager::endpointType();
    }

    private static function friendlyError(string $category, string $technicalError = ''): string
    {
        $lower = strtolower($technicalError);

        if (str_contains($lower, 'revoc')) {
            return Tools::trans('error-certificate-revoked');
        }

        if (str_contains($lower, 'caduc') || str_contains($lower, 'expired') || str_contains($lower, 'expirado')) {
            return Tools::trans('error-certificate-expired');
        }

        if (str_contains($lower, '401') || str_contains($lower, '403') || str_contains($lower, 'forbidden') || str_contains($lower, 'unauthorized') || str_contains($lower, 'no autorizado')) {
            return Tools::trans('error-certificate-unauthorized');
        }

        if (str_contains($lower, 'codigo[103]') || str_contains($lower, 'localpart') || str_contains($lower, 'namespace') || str_contains($lower, 'etiqueta')) {
            return Tools::trans('error-soap-format');
        }

        if ($category === 'php-extension') {
            return Tools::trans('error-php-extension');
        }

        if ($category === 'certificate-passphrase') {
            return Tools::trans('error-certificate-passphrase');
        }

        if ($category === 'certificate') {
            return Tools::trans('error-certificate');
        }

        if ($category === 'aeat-response') {
            return Tools::trans('error-aeat-response');
        }

        if ($category === 'tls' || $category === 'endpoint') {
            return Tools::trans('error-endpoint');
        }

        if ($category === 'soap') {
            return Tools::trans('error-soap');
        }

        return Tools::trans('error-unknown');
    }

    private static function categorizeError(string $technicalError): string
    {
        $lower = strtolower($technicalError);

        if (str_contains($lower, 'extensi') || str_contains($lower, 'class "soapclient"') || str_contains($lower, 'soap: extensi')) {
            return 'php-extension';
        }
        if (str_contains($lower, 'contrase') || str_contains($lower, 'passphrase') || str_contains($lower, 'password')) {
            return 'certificate-passphrase';
        }
        if (str_contains($lower, 'revoc') || str_contains($lower, 'caduc') || str_contains($lower, 'expired') || str_contains($lower, 'not valid yet')) {
            return 'certificate';
        }
        if (str_contains($lower, 'certificado') || str_contains($lower, 'certificate') || str_contains($lower, 'private key') || str_contains($lower, 'pem')) {
            return 'certificate';
        }
        if (str_contains($lower, 'ssl') || str_contains($lower, 'tls') || str_contains($lower, 'handshake')) {
            return 'tls';
        }
        if (str_contains($lower, 'could not connect') || str_contains($lower, 'host') || str_contains($lower, 'resolve') || str_contains($lower, 'timeout') || str_contains($lower, 'timed out')) {
            return 'endpoint';
        }
        if (str_contains($lower, 'no acept') || str_contains($lower, 'forbidden') || str_contains($lower, '403') || str_contains($lower, '401') || str_contains($lower, 'http ')) {
            return 'aeat-response';
        }
        if (str_contains($lower, 'soap') || str_contains($lower, 'fault')) {
            return 'soap';
        }

        return 'unknown';
    }

    private static function isIdentified(string $result): bool
    {
        return strtoupper(trim($result)) === 'IDENTIFICADO';
    }

    private static function newDiagnosticId(): string
    {
        return 'VALNIF-' . gmdate('YmdHis') . '-' . strtoupper(substr(bin2hex(random_bytes(3)), 0, 6));
    }

    private static function shorten(string $value): string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }

        return substr($value, 0, self::DIAGNOSTIC_TEXT_LIMIT);
    }
}
