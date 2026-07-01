<?php

namespace FacturaScripts\Plugins\ValidaNIF\Controller;

use FacturaScripts\Core\Base\Controller;
use FacturaScripts\Core\Tools;
use FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF\CertificateManager;
use FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF\ValidatorService;
use FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF\RuntimeRequirements;
use Throwable;

class AdminValidaNIF extends Controller
{
    public bool $debugMode = false;

    public bool $hasCertificate = false;
    public bool $hasPassphrase = false;
    public array $requirements = [];
    public bool $requirementsOk = true;
    public string $endpointType = 'personal';
    public int $timeout = 30;
    public string $testNif = '';
    public string $testNombre = '';
    public array $lastTest = [];

    public function getPageData(): array
    {
        $data = parent::getPageData();
        $data['menu'] = 'admin';
        $data['title'] = Tools::trans('validanif');
        $data['icon'] = 'fa-solid fa-id-card';
        $data['ordernum'] = 140;
        return $data;
    }

    public function privateCore(&$response, $user, $permissions): void
    {
        parent::privateCore($response, $user, $permissions);

        $this->loadSettings();

        $action = (string)$this->request->inputOrQuery('action', '');
        if ($action !== '' && false === $this->validateFormToken()) {
            return;
        }

        switch ($action) {
            case 'save-app-settings':
                $this->saveAppSettingsAction();
                break;

            case 'upload-certificate':
                $this->uploadCertificateAction();
                break;

            case 'delete-certificate':
                $this->deleteCertificateAction();
                break;

            case 'test-validanif':
                $this->testConnectionAction();
                break;
        }

        $this->loadSettings();
    }

    private function loadSettings(): void
    {
        $this->debugMode = (bool)Tools::config('debug', false);
        $this->endpointType = $this->normalizeEndpointType((string)Tools::settings(ValidatorService::CERT_SETTINGS, 'endpoint_type', 'personal'));
        $this->timeout = $this->normalizeTimeout((int)Tools::settings(ValidatorService::APP_SETTINGS, 'timeout', 30));
        $this->hasCertificate = CertificateManager::hasCertificate();
        $this->hasPassphrase = CertificateManager::hasPassphrase((string)Tools::settings(ValidatorService::CERT_SETTINGS, 'passphrase', ''));
        $this->requirements = RuntimeRequirements::all();
        $this->requirementsOk = RuntimeRequirements::isOk($this->requirements);
    }

    private function saveAppSettingsAction(): void
    {
        if (false === $this->permissions->allowUpdate) {
            Tools::log()->warning(Tools::trans('no-permission'));
            return;
        }

        $this->timeout = $this->normalizeTimeout((int)$this->request->request->get('timeout', 30));

        Tools::settingsSet(ValidatorService::APP_SETTINGS, 'timeout', $this->timeout);
        Tools::settingsSave();

        Tools::log()->notice(Tools::trans('app-settings-saved'));
    }

    private function uploadCertificateAction(): void
    {
        if (false === $this->permissions->allowUpdate) {
            Tools::log()->warning(Tools::trans('no-permission'));
            return;
        }

        $endpointType = $this->normalizeEndpointType((string)$this->request->request->get('endpoint_type', 'personal'));
        $passphrase = (string)$this->request->request->get('passphrase', '');
        $uploadedFile = $this->request->files->get('certificate');

        if ($uploadedFile === null) {
            Tools::log()->warning(Tools::trans('certificate-missing'));
            return;
        }

        $tmpPath = method_exists($uploadedFile, 'getPathname')
            ? $uploadedFile->getPathname()
            : (string)($uploadedFile['tmp_name'] ?? '');

        $hasUpload = $tmpPath !== '' && is_readable($tmpPath) && filesize($tmpPath) > 0;
        if (false === $hasUpload) {
            Tools::log()->warning(Tools::trans('certificate-empty'));
            return;
        }

        if ($passphrase === '') {
            Tools::log()->warning(Tools::trans('passphrase-missing'));
            return;
        }

        try {
            CertificateManager::saveP12($tmpPath, $passphrase);
            CertificateManager::savePassphrase($passphrase);

            Tools::settingsSet(ValidatorService::CERT_SETTINGS, 'endpoint_type', $endpointType);
            Tools::settingsSet(ValidatorService::CERT_SETTINGS, 'passphrase', $passphrase);
            Tools::settingsSet(ValidatorService::CERT_SETTINGS, 'cert_uploaded', 1);
            Tools::settingsSave();

            Tools::log()->notice(Tools::trans('certificate-save-ok'));
        } catch (Throwable $exception) {
            $reference = ValidatorService::errorDiagnostic(
                'config',
                'certificate',
                'certificate',
                $exception->getMessage(),
                ['action' => 'upload-certificate']
            );
            Tools::log()->warning(Tools::trans('diagnostic-reference', [
                '%reference%' => $reference,
            ]));
            Tools::log()->warning(Tools::trans('certificate-save-error'));
            Tools::log()->warning(Tools::trans('certificate-save-unchanged'));
        }
    }

    private function deleteCertificateAction(): void
    {
        if (false === $this->permissions->allowUpdate) {
            Tools::log()->warning(Tools::trans('no-permission'));
            return;
        }

        CertificateManager::deleteCertificate();
        Tools::settingsSet(ValidatorService::CERT_SETTINGS, 'cert_uploaded', 0);
        Tools::settingsSet(ValidatorService::CERT_SETTINGS, 'passphrase', '');
        Tools::settingsSave();
        Tools::log()->notice(Tools::trans('certificate-deleted'));
    }

    private function testConnectionAction(): void
    {
        $this->testNif = trim((string)$this->request->request->get('test_nif', ''));
        $this->testNombre = trim((string)$this->request->request->get('test_nombre', ''));

        if ($this->testNif === '') {
            Tools::log()->warning(Tools::trans('test-missing-data'));
            return;
        }

        $blockingErrors = RuntimeRequirements::blockingErrors($this->requirements);
        if (!empty($blockingErrors)) {
            $message = Tools::trans('server-requirements-error') . ' ' . implode(' ', $blockingErrors);
            $reference = ValidatorService::errorDiagnostic('test', 'test', 'php-extension', $message);
            $this->lastTest = [
                'ok' => false,
                'error' => Tools::trans('server-requirements-error'),
                'reference' => $reference,
            ];
            return;
        }

        $service = new ValidatorService();
        $this->lastTest = $service->validateParty(
            'test',
            'test',
            $this->testNif,
            $this->testNombre,
            $this->user->nick ?? ''
        );

        if ($this->lastTest['ok'] ?? false) {
            return;
        }
    }

    private function normalizeEndpointType(string $endpointType): string
    {
        return $endpointType === 'sello' ? 'sello' : 'personal';
    }

    private function normalizeTimeout(int $timeout): int
    {
        return max(5, min(300, $timeout));
    }
}
