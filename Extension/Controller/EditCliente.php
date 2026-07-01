<?php

namespace FacturaScripts\Plugins\ValidaNIF\Extension\Controller;

use Closure;
use FacturaScripts\Core\Tools;
use FacturaScripts\Dinamic\Model\Cliente;
use FacturaScripts\Plugins\ValidaNIF\Lib\ValidaNIF\ValidatorService;

class EditCliente
{
    public function loadData(): Closure
    {
        return function ($viewName, $view) {
            if ($viewName !== $this->getMainViewName()) {
                return;
            }
    
            if (false === $view->model->exists() || empty($view->model->cifnif)) {
                return;
            }
    
            $view->addButton([
                'action' => 'validanif-validate-customer',
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

            if ($action !== 'validanif-validate-customer') {
                return true;
            }

            $redirectWithMessage = function (string $url, string $urlAction, string $message): void {
                $separator = strpos($url, '?') === false ? '?' : '&';
                $shortMessage = substr($message, 0, 1000);
                $this->redirect($url . $separator . 'action=' . $urlAction . '&validanif_msg=' . urlencode($shortMessage));
            };

            $code = (string)$this->request->queryOrInput('code');
            $cliente = new Cliente();
            if ($code === '' || false === $cliente->loadFromCode($code)) {
                Tools::log()->warning(Tools::trans('load-customer-error'));
                return false;
            }

            if (empty($cliente->cifnif)) {
                $redirectWithMessage($cliente->url(), 'validation-error-title', Tools::trans('missing-customer-nif'));
                return false;
            }

            $razonSocial = trim((string)($cliente->razonsocial ?? ''));
            $nombreAEAT = $razonSocial !== '' ? $razonSocial : (string)$cliente->nombre;

            $service = new ValidatorService();
            $response = $service->validateParty(
                'cliente',
                (string)$cliente->codcliente,
                (string)$cliente->cifnif,
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
                $redirectWithMessage($cliente->url(), 'validanif-ok', $message);
                return false;
            }

            if (isset($response['result'])) {
                $message = Tools::trans('result-error-message', [
                    '%result%' => $response['result']['resultado'] ?? Tools::trans('error-unknown'),
                ]);
                $redirectWithMessage($cliente->url(), 'validation-error-title', $message);
                return false;
            }

            $message = $response['error'] ?? Tools::trans('error-unknown');
            if (!empty($response['reference'])) {
                $message = Tools::trans('technical-error-with-reference', [
                    '%message%' => $message,
                    '%reference%' => $response['reference'],
                ]);
            }
            $redirectWithMessage($cliente->url(), 'validation-error-title', $message);
            return false;
        };
    }
}
