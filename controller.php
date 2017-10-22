<?php

namespace Concrete\Package\ComposerSecurity;

use Concrete\Core\Config\Repository\Repository;
use Concrete\Core\Job\Job;
use Concrete\Core\Package\Package as BasePackage;
use Concrete\Core\Support\Facade\Package;

class Controller extends BasePackage
{
    protected $pkgHandle = 'composer_security';
    protected $appVersionRequired = '8.1';
    protected $pkgVersion = '1.0';
    protected $pkgAutoloaderRegistries = [
        'src/ComposerSecurity' => '\A3020\ComposerSecurity',
    ];

    public function getPackageName()
    {
        return t('Composer Security');
    }

    public function getPackageDescription()
    {
        return t('Installs a job that checks your composer files for vulnerabilities.');
    }

    public function install()
    {
        parent::install();

        $this->installJob($this);
        $this->setupConfiguration();
    }

    public function upgrade()
    {
        $pkg = Package::getByHandle('composer_security');
        $this->installJob($pkg);
    }

    protected function installJob($pkg)
    {
        $job = Job::getByHandle('composer_security');
        if (!$job) {
            Job::installByPackage('composer_security', $pkg);
        }
    }

    /**
     * Only run this when package is installed, not when upgraded.
     */
    protected function setupConfiguration()
    {
        /** @var \Concrete\Core\User\UserInfo $superUser */
        $superUser = $this->app->make(\Concrete\Core\User\UserInfoRepository::class)->getByID(1);

        $config = $this->app->make(Repository::class);
        $config->save('composer_security.enable_notifications', true);
        $config->save('composer_security.recipients', [$superUser->getUserEmail()]);
    }
}
