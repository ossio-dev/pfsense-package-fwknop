<?php
/*
 * fwknop.priv.inc
 *
 * pfSense privilege definitions for the fwknop package GUI.
 */

global $priv_list;

$priv_list['page-services-fwknop'] = array();
$priv_list['page-services-fwknop']['name'] = "WebCfg - Services: fwknop package";
$priv_list['page-services-fwknop']['descr'] = "Allow access to fwknop package GUI";
$priv_list['page-services-fwknop']['match'] = array();
$priv_list['page-services-fwknop']['match'][] = "pkg_edit.php?xml=fwknop.xml*";
$priv_list['page-services-fwknop']['match'][] = "pkg.php?xml=fwknop.xml*";
$priv_list['page-services-fwknop']['match'][] = "packages/fwknop/index.php*";
$priv_list['page-services-fwknop']['match'][] = "packages/fwknop/edit.php*";
$priv_list['page-services-fwknop']['match'][] = "packages/fwknop/status.php*";

?>
