<?php

namespace A3020\ComposerSecurity;

use Concrete\Core\Application\Application;
use Concrete\Core\Config\Repository\Repository;
use SensioLabs\Security\SecurityChecker;

final class Helper
{
    /** @var Application */
    private $app;

    /** @var Repository */
    private $config;

    /** @var SecurityChecker */
    private $checker;

    /**
     * @param Application     $app
     * @param Repository      $config
     * @param SecurityChecker $checker
     */
    public function __construct(Application $app, Repository $config, SecurityChecker $checker)
    {
        $this->app = $app;
        $this->config = $config;
        $this->checker = $checker;
    }

    /**
     * @param string $lockFileLocation
     *
     * @return array an array of two items: an array of vulnerabilities and the number of vulnerabilities
     */
    public function checkComposerLockFile($lockFileLocation)
    {
        return [$this->checker->check($lockFileLocation), $this->checker->getLastVulnerabilityCount()];
    }

    /**
     * @param array $vulnerabilities
     *
     * @return bool
     */
    public function sendNotification($vulnerabilities)
    {
        // Don't send a notification if it is disabled in the config.
        if (!$this->config->get('composer_security.enable_notifications')) {
            return false;
        }

        $recipients = $this->getRecipients();
        if (count($recipients) === 0) {
            return false;
        }

        /** @var \Concrete\Core\Mail\Service $mh */
        $mh = $this->app->make('mail');
        foreach ($recipients as $recipient) {
            $mh->to($recipient);
        }

        $mh->addParameter('vulnerabilities', $vulnerabilities);
        $mh->load('notification', 'composer_security');

        return $mh->sendMail();
    }

    /**
     * Returns array of recipients (email addresses).
     *
     * Recipients can be defined in the config:
     * /application/config/generated_overrides/composer_security.php
     *
     * @return array
     */
    private function getRecipients()
    {
        $recipients = $this->config->get('composer_security.recipients');
        $recipients = array_map('trim', $recipients);

        return array_filter($recipients);
    }
}
