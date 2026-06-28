<?php

namespace FacturaScripts\Plugins\ValidaNIF;

use FacturaScripts\Core\Template\InitClass;
use FacturaScripts\Core\Tools;
use FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF\CertificateManager;
use FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF\ValidatorService;

final class Init extends InitClass
{
    public function init(): void
    {
        $this->loadExtension(new Extension\Controller\EditCliente());
        $this->loadExtension(new Extension\Controller\EditProveedor());
    }

    public function update(): void
    {
        if ((int)Tools::settings(ValidatorService::APP_SETTINGS, 'timeout', 0) <= 0) {
            Tools::settingsSet(ValidatorService::APP_SETTINGS, 'timeout', 30);
        }
        if (Tools::settings(ValidatorService::CERT_SETTINGS, 'endpoint_type', '') === '') {
            Tools::settingsSet(ValidatorService::CERT_SETTINGS, 'endpoint_type', 'personal');
        }

        Tools::settingsSet(ValidatorService::CERT_SETTINGS, 'cert_uploaded', CertificateManager::hasCertificate() ? 1 : 0);
        Tools::settingsSave();
    }

    public function uninstall(): void
    {
        // No borramos el certificado automaticamente para evitar perdida accidental.
    }
}
