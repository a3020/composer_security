<?php

namespace Concrete\Package\ComposerSecurity\Job;

use A3020\ComposerSecurity\Helper;
use Concrete\Core\Job\Job;
use Concrete\Core\Package\PackageService;
use Concrete\Core\Support\Facade\Application;
use Exception;
use Symfony\Component\Finder\Finder;

class ComposerSecurity extends Job
{
    /** @var \Concrete\Core\Application\Application Not named 'app' on purpose (parent class might change). */
    protected $appInstance;

    /** @var \A3020\ComposerSecurity\Helper $helper */
    protected $helper;

    protected $listOfVulnerabilities = [];
    protected $totalNumberOfVulnerabilities = 0;

    public function getJobName()
    {
        return t('Composer Security Checker');
    }

    public function getJobDescription()
    {
        return t('Checks composer files against SensioLabs Security Checker.');
    }

    public function run()
    {
        $this->appInstance = Application::getFacadeApplication();

        try {
            $packageService = $this->appInstance->make(PackageService::class);
            $pkg = $packageService->getByHandle('composer_security');
            require_once $pkg->getPackagePath()."/vendor/autoload.php";

            $this->helper = $this->appInstance->make(Helper::class);

            $fileLocations = $this->getComposerLockFileLocations();
            $numberOfFileLocations = count($fileLocations);
            $this->checkForSecurityIssues($fileLocations);

            $msg = t2(
                'One composer.lock file found.',
                '%d composer.lock files found.',
                $numberOfFileLocations,
                $numberOfFileLocations
            ).' ';

            if ($this->totalNumberOfVulnerabilities === 0) {
                return $msg.t('No vulnerabilities.');
            }

            $this->helper->sendNotification($this->listOfVulnerabilities);

            return $msg.t2(
                'One vulnerability found.',
                '%d vulnerabilities found.',
                $this->totalNumberOfVulnerabilities,
                $this->totalNumberOfVulnerabilities
            );
        } catch (Exception $e) {
            /** @var \Concrete\Core\Logging\Logger $log */
            $log = $this->appInstance->make('log/exceptions');
            $log->addError('Composer Security: '.$e->getMessage().' '.$e->getTraceAsString());

            return t('Something went wrong. Please check the log.');
        }
    }

    /**
     * @param Finder $lockFileLocations
     */
    private function checkForSecurityIssues($lockFileLocations)
    {
        foreach ($lockFileLocations as $lockFileLocation) {
            $lockFileLocation = (string) $lockFileLocation;
            list($vulnerabilities, $numberOfVulnerabilities) = $this->helper->checkComposerLockFile($lockFileLocation);
            if ($numberOfVulnerabilities === 0) {
                continue;
            }

            $this->totalNumberOfVulnerabilities += $numberOfVulnerabilities;
            $this->listOfVulnerabilities[$lockFileLocation] = $vulnerabilities;
        }
    }

    /**
     * Return array with composer.lock locations.
     *
     * @return Finder
     */
    private function getComposerLockFileLocations()
    {
        $finder = new Finder();

        return $finder->name('composer.lock')
            ->ignoreDotFiles(true)
            ->ignoreUnreadableDirs(true)
            ->ignoreVCS(true)
            ->in(DIR_BASE)
            ->exclude([
                DIR_FILES_UPLOADED_STANDARD,
                DIR_BASE_CORE,
            ])
            ->files();
    }
}
