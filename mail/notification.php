<?php

defined('C5_EXECUTE') or die("Access Denied.");

$subject = t('Composer Security warning');
$body = t("Dear administrator,

The Composer Security job has found one or more vulnerabilities in your composer.json file(s).
");

$bodyHTML = t("Dear administrator,<br><br>

The Composer Security job has found one or more vulnerabilities in your composer.json file(s).<br><br>");

/**
 * @var array $vulnerabilities
 * @var string $lockfile
 * @var array $vulnerability
 */
foreach ($vulnerabilities as $lockfile => $vulnerability) {
    $body .= "\r\n----------------------------------------------------------------\r\n" . $lockfile;
    $bodyHTML .= "<hr><br>".$lockfile."<br>";

    foreach ($vulnerability as $package => $report) {
        $body .= "\r\n\r\n" . $package . " - " . $report['version'] . "\r\n";
        $bodyHTML .= "<h4>" . $package . " - " . $report['version'] . "</h4>";
        $bodyHTML .= '<ul>';

        foreach ($report['advisories'] as $key => $information) {
            $body .= "* " .
                $information['title'] . " | " .
                (($information['cve']) ? $information['cve'] . " | " : "") .
                $information['link'] .
                "\r\n";
            $bodyHTML .= '<li>' .
                $information['title'] . ' | ' .
                (($information['cve']) ? $information['cve'] . ' | ' : '') .
                $information['link'] .
                '</li>';
        }
        $bodyHTML .= '</ul><br>';
    }
}
