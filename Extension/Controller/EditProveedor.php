<?php

namespace FacturaScripts\Plugins\ValidaNIF\Extension\Controller;

use Closure;
use FacturaScripts\Core\Tools;
use FacturaScripts\Dinamic\Model\Proveedor;
use FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF\ValidatorService;

class EditProveedor
{
    public function createViews(): Closure
    {
        return function () {
            $viewName = $this->getMainViewName();
            $this->tab($viewName)->addButton([
                'action' => 'validanif-validate-supplier',
                'color' => 'info',
                'icon' => 'fa-solid fa-id-card',
                'label' => 'validar-nif',
                'type' => 'button',
            ]);
        };
    }

    public function execPreviousAction(): Closure
    {
        return function ($action) {
            if ($action === 'validanif-ok') {
                Tools::log()->notice((string)$this->request->queryOrInput('validanif_msg', Tools::trans('validation-ok')));
                return true;
            }

            if ($action === 'validation-error-title') {
                Tools::log()->warning((string)$this->request->queryOrInput('validanif_msg', Tools::trans('validation-error')));
                return true;
            }

            if ($action !== 'validanif-validate-supplier') {
                return true;
            }

            $redirectWithMessage = function (string $url, string $urlAction, string $message): void {
                $separator = strpos($url, '?') === false ? '?' : '&';
                $shortMessage = substr($message, 0, 1000);
                $this->redirect($url . $separator . 'action=' . $urlAction . '&validanif_msg=' . urlencode($shortMessage));
            };

            $code = (string)$this->request->queryOrInput('code');
            $proveedor = new Proveedor();
            if ($code === '' || false === $proveedor->loadFromCode($code)) {
                Tools::log()->warning(Tools::trans('load-supplier-error'));
                return false;
            }

            if (empty($proveedor->cifnif)) {
                $redirectWithMessage($proveedor->url(), 'validation-error-title', Tools::trans('missing-supplier-nif'));
                return false;
            }

            $razonSocial = trim((string)($proveedor->razonsocial ?? ''));
            $nombreAEAT = $razonSocial !== '' ? $razonSocial : (string)$proveedor->nombre;

            $service = new ValidatorService();
            $response = $service->validateParty(
                'proveedor',
                (string)$proveedor->codproveedor,
                (string)$proveedor->cifnif,
                $nombreAEAT,
                $this->user->nick ?? ''
            );

            if ($response['ok'] ?? false) {
                $result = $response['result'];
                $message = Tools::trans('result-ok-message', [
                    '%result%' => $result['resultado'],
                    '%nif%' => $result['nif'],
                    '%name%' => $result['nombre_aeat'] ?? $result['nombre'],
                ]);
                $redirectWithMessage($proveedor->url(), 'validanif-ok', $message);
                return false;
            }

            if (isset($response['result'])) {
                $message = Tools::trans('result-error-message', [
                    '%result%' => $response['result']['resultado'] ?? Tools::trans('error-unknown'),
                ]);
                $redirectWithMessage($proveedor->url(), 'validation-error-title', $message);
                return false;
            }

            $message = $response['error'] ?? Tools::trans('error-unknown');
            if (!empty($response['reference'])) {
                $message = Tools::trans('technical-error-with-reference', [
                    '%message%' => $message,
                    '%reference%' => $response['reference'],
                ]);
            }
            $redirectWithMessage($proveedor->url(), 'validation-error-title', $message);
            return false;
        };
    }
}
