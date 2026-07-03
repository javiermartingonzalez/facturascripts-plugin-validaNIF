<?php

namespace FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF;

use DOMDocument;
use DOMXPath;
use FacturaScripts\Core\Tools;
use RuntimeException;
use SoapClient;
use SoapFault;

final class AeatNifClient
{
    public const ENDPOINT_PERSONAL = 'https://www1.agenciatributaria.gob.es/wlpl/BURT-JDIT/ws/VNifV2SOAP';
    public const ENDPOINT_SELLO = 'https://www10.agenciatributaria.gob.es/wlpl/BURT-JDIT/ws/VNifV2SOAP';

    private string $lastRequest = '';
    private string $lastResponse = '';
    private string $lastTransport = '';
    private string $lastSoapError = '';

    public function __construct(
        private readonly string $certificatePath,
        private readonly string $passphrase,
        private readonly string $endpoint = self::ENDPOINT_PERSONAL,
        private readonly int $timeout = 30
    ) {
    }

    /**
     * @return array{nif:string,nombre:string,nombre_aeat:string,resultado:string}
     */
    public function validateOne(string $nif, string $nombre): array
    {
        $rows = $this->validateMany([
            ['Nif' => self::cleanNif($nif), 'Nombre' => self::cleanName($nombre)]
        ]);

        return $rows[0] ?? [
            'nif' => $nif,
            'nombre' => $nombre,
            'nombre_aeat' => $nombre,
            'resultado' => Tools::trans('result-no-response')
        ];
    }

    /**
     * @param array<int,array{Nif:string,Nombre:string}> $contributors
     * @return array<int,array{nif:string,nombre:string,nombre_aeat:string,resultado:string}>
     */
    public function validateMany(array $contributors): array
    {
        $this->checkConfiguration();

        if (!class_exists(SoapClient::class)) {
            $this->lastSoapError = 'SOAP: ' . Tools::trans('soap-extension-missing');
            throw new RuntimeException($this->lastSoapError);
        }

        try {
            return $this->validateManyWithSoapClient($contributors);
        } catch (SoapFault $fault) {
            $this->lastSoapError = 'SOAP: ' . $fault->getMessage();
            throw new RuntimeException($this->lastSoapError, 0, $fault);
        } catch (RuntimeException $exception) {
            $this->lastSoapError = 'SOAP: ' . $exception->getMessage();
            throw $exception;
        }
    }
    public function getLastRequest(): string
    {
        return $this->lastRequest;
    }

    public function getLastResponse(): string
    {
        return $this->lastResponse;
    }

    public function getLastTransport(): string
    {
        return $this->lastTransport;
    }

    /**
     * @return array{endpoint:string,transport:string,soap_error:string}
     */
    public function getDiagnosticContext(): array
    {
        return [
            'endpoint' => $this->endpoint,
            'transport' => $this->lastTransport,
            'soap_error' => $this->lastSoapError,
        ];
    }

    public static function endpointFromType(string $endpointType): string
    {
        return $endpointType === 'sello' ? self::ENDPOINT_SELLO : self::ENDPOINT_PERSONAL;
    }

    public static function wsdlPath(): string
    {
        return __DIR__ . DIRECTORY_SEPARATOR . 'Wsdl' . DIRECTORY_SEPARATOR . 'VNifV2.wsdl';
    }

    /**
     * @param array<int,array{Nif:string,Nombre:string}> $contributors
     * @return array<int,array{nif:string,nombre:string,nombre_aeat:string,resultado:string}>
     */
    private function validateManyWithSoapClient(array $contributors): array
    {
        $this->lastTransport = 'soap';
        $wsdl = self::wsdlPath();
        if (!is_readable($wsdl)) {
            throw new RuntimeException(Tools::trans('wsdl-missing'));
        }

        $options = [
            'local_cert' => $this->certificatePath,
            'passphrase' => $this->passphrase,
            'trace' => true,
            'exceptions' => true,
            'cache_wsdl' => WSDL_CACHE_NONE,
            'connection_timeout' => $this->timeout,
            'stream_context' => stream_context_create([
                'http' => [
                    'timeout' => $this->timeout,
                ],
                'ssl' => [
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                    'allow_self_signed' => false,
                    'crypto_method' => 33,
                ]
            ]),
            'soap_version' => SOAP_1_1,
            'style' => SOAP_DOCUMENT,
            'use' => SOAP_LITERAL,
        ];

        set_error_handler(static function (int $errno, string $errstr) use ($wsdl): bool {
            if ($errno === E_WARNING || $errno === E_NOTICE) {
                throw new SoapFault('Client', Tools::trans('soap-client-init-error', [
                    '%error%' => $errstr,
                    '%wsdl%' => $wsdl,
                ]));
            }

            return false;
        });

        try {
            $client = new SoapClient($wsdl, $options);
        } finally {
            restore_error_handler();
        }

        try {
            $client->__setLocation($this->endpoint);
            $this->lastRequest = $this->buildSoapEnvelope($contributors);
            $this->lastResponse = (string)$client->__doRequest(
                $this->lastRequest,
                $this->endpoint,
                '',
                SOAP_1_1
            );
        } catch (SoapFault $fault) {
            if (isset($client)) {
                $this->lastRequest = $this->lastRequest !== '' ? $this->lastRequest : (string)$client->__getLastRequest();
                $this->lastResponse = (string)$client->__getLastResponse();
            }
            throw $fault;
        }

        return $this->parseSoapResponse($this->lastResponse);
    }

    private function checkConfiguration(): void
    {
        if (!is_readable($this->certificatePath)) {
            throw new RuntimeException(Tools::trans('configured-certificate-missing'));
        }
        if ($this->passphrase === '') {
            throw new RuntimeException(Tools::trans('configured-passphrase-missing'));
        }
    }

    /**
     * @param array<int,array{Nif:string,Nombre:string}> $contributors
     */
    private function buildSoapEnvelope(array $contributors): string
    {
        $xml = '<?xml version="1.0" encoding="UTF-8"?>'
            . '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:vnif="http://www2.agenciatributaria.gob.es/static_files/common/internet/dep/aplicaciones/es/aeat/burt/jdit/ws/VNifV2Ent.xsd">'
            . '<soapenv:Header/><soapenv:Body><vnif:VNifV2Ent>';

        foreach ($contributors as $contributor) {
            $xml .= '<vnif:Contribuyente>'
                . '<vnif:Nif>' . self::xml($contributor['Nif'] ?? '') . '</vnif:Nif>'
                . '<vnif:Nombre>' . self::xml($contributor['Nombre'] ?? '') . '</vnif:Nombre>'
                . '</vnif:Contribuyente>';
        }

        return $xml . '</vnif:VNifV2Ent></soapenv:Body></soapenv:Envelope>';
    }

    /**
     * @return array<int,array{nif:string,nombre:string,nombre_aeat:string,resultado:string}>
     */
    private function parseSoapResponse(string $xml): array
    {
        $fault = $this->extractFaultString($xml);
        if ($fault !== '') {
            throw new RuntimeException(Tools::trans('aeat-request-rejected') . ' ' . $fault);
        }

        $dom = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $loaded = $dom->loadXML($xml);
        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if (!$loaded) {
            throw new RuntimeException(Tools::trans('aeat-response-unreadable'));
        }

        $xpath = new DOMXPath($dom);
        $nodes = $xpath->query('//*[local-name()="Contribuyente"]');
        if ($nodes === false || $nodes->length === 0) {
            throw new RuntimeException(Tools::trans('aeat-response-without-contributor'));
        }

        $rows = [];
        foreach ($nodes as $node) {
            $nombreAeAT = $this->childText($node, 'Nombre');
            $rows[] = [
                'nif' => $this->childText($node, 'Nif'),
                'nombre' => $nombreAeAT,
                'nombre_aeat' => $nombreAeAT,
                'resultado' => $this->childText($node, 'Resultado'),
            ];
        }

        return $rows;
    }

    private function extractFaultString(string $xml): string
    {
        if (trim($xml) === '') {
            return '';
        }

        $dom = new DOMDocument();
        $previous = libxml_use_internal_errors(true);
        $loaded = $dom->loadXML($xml);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);
        if (!$loaded) {
            return '';
        }

        $xpath = new DOMXPath($dom);
        $nodes = $xpath->query('//*[local-name()="faultstring"]');
        if ($nodes !== false && $nodes->length > 0) {
            return trim($nodes->item(0)->textContent);
        }

        return '';
    }

    private function childText(\DOMNode $node, string $localName): string
    {
        foreach ($node->childNodes as $child) {
            if ($child->localName === $localName) {
                return trim($child->textContent);
            }
        }

        return '';
    }

    private static function cleanNif(string $nif): string
    {
        return strtoupper(trim(str_replace([' ', '-', '.'], '', $nif)));
    }

    private static function cleanName(string $nombre): string
    {
        return trim(preg_replace('/\s+/u', ' ', $nombre) ?? $nombre);
    }

    private static function xml(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_COMPAT, 'UTF-8');
    }
}
