<?php
/*
 * fwknop.inc
 *
 * pfSense package integration for fwknopd Single Packet Authorization.
 */

require_once("config.inc");
require_once("filter.inc");
require_once("interfaces.inc");
require_once("service-utils.inc");
require_once("services.inc");
require_once("util.inc");

define('FWKNOP_CONFIG_PATH', 'installedpackages/fwknop/config/0');
define('FWKNOP_RULE_PATH', 'fwknop/accessrule');
define('FWKNOP_LEGACY_RULE_PATH', 'installedpackages/fwknop/rule');
define('FWKNOP_LEGACY_PACKAGE_RULE_PATH', 'installedpackages/fwknop/accessrule');
define('FWKNOP_LEGACY_CONFIG_RULE_PATH', 'installedpackages/fwknop/config/0/accessrule');
define('FWKNOP_ETCDIR', '/usr/local/etc/fwknop');
define('FWKNOP_ACCESS_D_DIR', FWKNOP_ETCDIR . '/access.d');
define('FWKNOP_FWKNOPD_CONF', FWKNOP_ETCDIR . '/fwknopd.conf');
define('FWKNOP_ACCESS_CONF', FWKNOP_ETCDIR . '/access.conf');
define('FWKNOP_TABLE_HELPER', '/usr/local/sbin/pfsense-fwknop-table');
define('FWKNOPD_BINARY', '/usr/local/sbin/fwknopd');
define('FWKNOP_RC_SCRIPT', '/usr/local/etc/rc.d/fwknopd');
define('LOG_PREFIX_PKG_FWKNOP', 'fwknop');

function fwknop_default_settings() {
	return [
		'enabled' => 'off',
		'listen_interfaces' => '',
		'spa_port' => '62201',
		'pcap_filter_override' => '',
		'log_level' => '0',
		'syslog_enabled' => 'on',
		'managed_pf_table_mode' => 'on',
		'allow_raw_advanced_config' => 'off',
		'raw_advanced_config' => ''
	];
}

function fwknop_get_settings() {
	$settings = config_get_path(FWKNOP_CONFIG_PATH, []);
	if (!is_array($settings)) {
		$settings = [];
	}

	return array_replace(fwknop_default_settings(), $settings);
}

function fwknop_runtime_components() {
	return [
		gettext('fwknopd binary') => FWKNOPD_BINARY,
		gettext('fwknopd rc script') => FWKNOP_RC_SCRIPT
	];
}

function fwknop_runtime_missing_components() {
	$missing = [];
	foreach (fwknop_runtime_components() as $name => $path) {
		if (!file_exists($path) || !is_executable($path)) {
			$missing[] = [
				'name' => $name,
				'path' => $path
			];
		}
	}

	return $missing;
}

function fwknop_runtime_available() {
	return empty(fwknop_runtime_missing_components());
}

function fwknop_runtime_status_message() {
	$missing = fwknop_runtime_missing_components();
	if (empty($missing)) {
		return '';
	}

	$details = [];
	foreach ($missing as $component) {
		$details[] = sprintf('%s (%s)', $component['name'], $component['path']);
	}

	return sprintf(
		gettext('fwknop runtime components are missing: %s. Install the security/fwknop runtime package before enabling or restarting the pfSense fwknop package.'),
		implode(', ', $details)
	);
}

function fwknop_install_command() {
	fwknop_make_directories();

	$changed = false;
	foreach (fwknop_default_settings() as $key => $value) {
		if (config_get_path(FWKNOP_CONFIG_PATH . "/{$key}") === null) {
			config_set_path(FWKNOP_CONFIG_PATH . "/{$key}", $value);
			$changed = true;
		}
	}

	if ($changed) {
		write_config('fwknop package defaults installed');
	}

	fwknop_resync_config();
}

function fwknop_deinstall_command() {
	fwknop_stop();
	fwknop_remove_generated_files();
}

function fwknop_can_reload_filter() {
	return function_exists('filter_configure') &&
		(!function_exists('platform_booting') || !platform_booting());
}

function fwknop_reload_filter() {
	if (fwknop_can_reload_filter()) {
		filter_configure();
	}
}

function fwknop_resync_config() {
	$settings = fwknop_get_settings();

	if (!fwknop_is_enabled($settings)) {
		fwknop_stop();
		fwknop_remove_generated_files();
		fwknop_reload_filter();
		return;
	}

	fwknop_make_directories();
	fwknop_generate_fwknopd_conf();
	fwknop_generate_access_conf();

	if (function_exists('fwknop_write_table_helper')) {
		fwknop_write_table_helper();
	}

	if (!fwknop_runtime_available()) {
		fwknop_log_warning(fwknop_runtime_status_message());
		fwknop_reload_filter();
		return;
	}

	if (fwknop_can_reload_filter()) {
		fwknop_reload_filter();
	}

	if (!function_exists('platform_booting') || !platform_booting()) {
		fwknop_restart();
	}
}

function fwknop_validate_config($post, &$input_errors) {
	$settings = array_replace(fwknop_default_settings(), is_array($post) ? $post : []);
	$spa_port = fwknop_array_get($settings, 'spa_port', '62201');

	if (!fwknop_is_port($spa_port)) {
		$input_errors[] = gettext("The SPA packet port must be a number from 1 through 65535.");
	}

	$listen_interfaces = fwknop_normalize_list(fwknop_array_get($settings, 'listen_interfaces', fwknop_array_get($settings, 'interface', [])));
	if (fwknop_is_enabled($settings) && empty($listen_interfaces)) {
		$input_errors[] = gettext("Select at least one interface for fwknopd to listen on.");
	}
	foreach ($listen_interfaces as $interface) {
		if (!fwknop_is_valid_interface($interface)) {
			$input_errors[] = sprintf(gettext("The listen interface '%s' is not a valid pfSense interface."), $interface);
		}
	}
	if (count($listen_interfaces) > 1) {
		$input_errors[] = gettext("Select only one listen interface. The current fwknop package integration supports a single capture interface.");
	}

	if (fwknop_is_enabled($settings) && !fwknop_runtime_available()) {
		$input_errors[] = fwknop_runtime_status_message();
	}

	$pcap_filter = trim((string)fwknop_array_get($settings, 'pcap_filter_override', ''));
	if (!fwknop_is_safe_config_value($pcap_filter, true)) {
		$input_errors[] = gettext("The packet capture filter override contains invalid control characters.");
	}

	$log_level = (string)fwknop_array_get($settings, 'log_level', '0');
	if (!fwknop_normalize_log_level($log_level, true)) {
		$input_errors[] = gettext("The log level must be one of 0, 1, 2, 3, info, verbose, or debug.");
	}

	if (fwknop_is_enabled(fwknop_array_get($settings, 'allow_raw_advanced_config', 'off'))) {
		$raw_config = (string)fwknop_array_get($settings, 'raw_advanced_config', '');
		if (strpos($raw_config, "\0") !== false) {
			$input_errors[] = gettext("Advanced raw configuration must not contain NUL bytes.");
		}
	}

	foreach (fwknop_get_posted_access_rules($post) as $index => $rule) {
		fwknop_validate_access_rule($rule, $index, $input_errors);
	}
}

function fwknop_service_status() {
	if (!fwknop_runtime_available()) {
		return false;
	}

	if (function_exists('is_service_running')) {
		return is_service_running('fwknopd');
	}
	if (function_exists('isvalidproc')) {
		return isvalidproc('fwknopd');
	}
	if (function_exists('mwexec')) {
		return mwexec('/bin/pgrep -anf ' . escapeshellarg('fwknopd')) == 0;
	}

	return false;
}

function fwknop_start() {
	if (!fwknop_runtime_available()) {
		fwknop_log_warning(fwknop_runtime_status_message());
		return false;
	}

	if (function_exists('start_service')) {
		return start_service('fwknopd');
	}
	if (file_exists(FWKNOP_RC_SCRIPT) && function_exists('mwexec')) {
		return mwexec(FWKNOP_RC_SCRIPT . ' start');
	}

	return false;
}

function fwknop_stop() {
	if (!fwknop_runtime_available()) {
		return false;
	}

	if (function_exists('stop_service')) {
		return stop_service('fwknopd');
	}
	if (file_exists(FWKNOP_RC_SCRIPT) && function_exists('mwexec')) {
		return mwexec(FWKNOP_RC_SCRIPT . ' stop');
	}

	return false;
}

function fwknop_restart() {
	if (!fwknop_runtime_available()) {
		fwknop_log_warning(fwknop_runtime_status_message());
		return false;
	}

	if (function_exists('restart_service')) {
		return restart_service('fwknopd');
	}
	if (file_exists(FWKNOP_RC_SCRIPT) && function_exists('mwexec')) {
		return mwexec(FWKNOP_RC_SCRIPT . ' restart');
	}

	fwknop_stop();
	return fwknop_start();
}

function fwknop_generate_fwknopd_conf() {
	$settings = fwknop_get_settings();
	$content = fwknop_build_fwknopd_conf($settings);

	fwknop_atomic_write(FWKNOP_FWKNOPD_CONF, $content, 0644);
	return FWKNOP_FWKNOPD_CONF;
}

function fwknop_generate_access_conf() {
	$rules = fwknop_get_access_rules();
	$content = fwknop_build_access_conf($rules);

	fwknop_atomic_write(FWKNOP_ACCESS_CONF, $content, 0600);
	return FWKNOP_ACCESS_CONF;
}

function fwknop_build_fwknopd_conf($settings) {
	$settings = array_replace(fwknop_default_settings(), is_array($settings) ? $settings : []);
	$spa_port = fwknop_is_port($settings['spa_port']) ? $settings['spa_port'] : '62201';
	$interfaces = fwknop_get_real_interfaces(fwknop_normalize_list($settings['listen_interfaces']));
	if (count($interfaces) > 1) {
		fwknop_log_warning('Multiple fwknop listen interfaces were configured. Only the first interface will be used for fwknopd packet capture.');
		$interfaces = [reset($interfaces)];
	}
	$pcap_interface = reset($interfaces);
	$pcap_filter = trim((string)$settings['pcap_filter_override']);
	if ($pcap_filter === '') {
		$pcap_filter = "udp port {$spa_port}";
	}

	$lines = [
		'# This file is generated by the pfSense fwknop package.',
		'# Manual edits will be overwritten.',
		'VERBOSE ' . fwknop_normalize_log_level($settings['log_level']) . ';'
	];

	if (!empty($pcap_interface)) {
		$lines[] = "PCAP_INTF {$pcap_interface};";
	}

	$lines[] = 'ENABLE_PCAP_PROMISC N;';
	$lines[] = "PCAP_FILTER {$pcap_filter};";
	$lines[] = 'ENABLE_UDP_SERVER Y;';
	$lines[] = "UDPSERV_PORT {$spa_port};";
	$lines[] = 'ENABLE_TCP_SERVER N;';
	if (fwknop_is_enabled($settings['syslog_enabled'])) {
		$lines[] = 'SYSLOG_IDENTITY fwknopd;';
		$lines[] = 'SYSLOG_FACILITY LOG_DAEMON;';
	}
	$lines[] = 'ENABLE_SPA_PACKET_AGING Y;';
	$lines[] = 'MAX_SPA_PACKET_AGE 120;';

	if (fwknop_is_enabled($settings['allow_raw_advanced_config']) &&
	    trim((string)$settings['raw_advanced_config']) !== '') {
		$lines[] = '';
		$lines[] = '# Advanced raw configuration from pfSense fwknop settings.';
		$lines[] = rtrim((string)$settings['raw_advanced_config']);
	}

	return implode("\n", $lines) . "\n";
}

function fwknop_build_access_conf($rules) {
	$lines = [
		'# This file is generated by the pfSense fwknop package.',
		'# It contains key material and must remain readable only by root.',
		''
	];

	foreach (fwknop_normalize_rule_list($rules) as $index => $rule) {
		if (!fwknop_is_enabled(fwknop_array_get($rule, 'enabled', fwknop_array_get($rule, 'enable', 'on')))) {
			continue;
		}

		$table = fwknop_table_name_for_rule($rule, $index);
		if (!fwknop_is_valid_table_name($table)) {
			continue;
		}

		$protocol = strtolower((string)fwknop_array_get($rule, 'protocol', 'tcp'));
		if (!in_array($protocol, ['tcp', 'udp'])) {
			continue;
		}

		$ports = fwknop_open_ports_for_rule($rule, $protocol);
		if (empty($ports)) {
			continue;
		}

		$timeout = fwknop_positive_int(fwknop_array_get($rule, 'timeout_seconds', '30'), 30);
		$source = fwknop_source_for_rule($rule);
		$destination = fwknop_destination_for_rule($rule);
		$description = fwknop_comment_value((string)fwknop_array_get($rule, 'description', "Rule {$index}"));
		$encryption_key = trim((string)fwknop_array_get($rule, 'encryption_key', ''));
		$hmac_key = trim((string)fwknop_array_get($rule, 'hmac_key', ''));

		if ($encryption_key === '' || $hmac_key === '') {
			continue;
		}

		$lines[] = "# {$description}";
		$lines[] = "SOURCE {$source};";
		if ($destination !== '') {
			$lines[] = "DESTINATION {$destination};";
		}
		$lines[] = 'OPEN_PORTS ' . implode(',', $ports) . ';';
		$lines[] = "FW_ACCESS_TIMEOUT {$timeout};";
		$lines[] = 'REQUIRE_SOURCE_ADDRESS Y;';
		$lines[] = "KEY_BASE64 {$encryption_key};";
		$lines[] = "HMAC_KEY_BASE64 {$hmac_key};";
		$lines[] = "CMD_CYCLE_OPEN " . FWKNOP_TABLE_HELPER . " open {$table} " . '$SRC $PROTO $PORT $CLIENT_TIMEOUT' . ';';
		$lines[] = "CMD_CYCLE_CLOSE " . FWKNOP_TABLE_HELPER . " close {$table} " . '$SRC $PROTO $PORT' . ';';
		$lines[] = '';
	}

	return implode("\n", $lines);
}

function fwknop_validate_access_rule($rule, $index, &$input_errors) {
	if (!is_array($rule) ||
	    !fwknop_is_enabled(fwknop_array_get($rule, 'enabled', fwknop_array_get($rule, 'enable', 'on')))) {
		return;
	}

	$description = trim((string)fwknop_array_get($rule, 'description', ''));
	if ($description === '' || !fwknop_is_safe_config_value($description, true)) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d needs a safe description."), $index + 1);
	}

	$source_type = strtolower((string)fwknop_array_get($rule, 'source_constraint_type', 'any'));
	$source_value = trim((string)fwknop_array_get($rule, 'source_constraint_value', ''));
	if (!in_array($source_type, ['any', 'ip', 'cidr', 'alias'])) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d has an invalid source constraint type."), $index + 1);
	} elseif (!fwknop_validate_source_constraint($source_type, $source_value)) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d has an invalid source constraint."), $index + 1);
	}

	$destination_type = strtolower((string)fwknop_array_get($rule, 'destination_type', 'firewall'));
	$destination_value = trim((string)fwknop_array_get($rule, 'destination_value', ''));
	if (!in_array($destination_type, ['firewall', 'interface', 'host', 'alias'])) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d has an invalid destination type."), $index + 1);
	} elseif (!fwknop_validate_destination($destination_type, $destination_value)) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d has an invalid destination."), $index + 1);
	}

	$protocol = strtolower((string)fwknop_array_get($rule, 'protocol', ''));
	if (!in_array($protocol, ['tcp', 'udp'])) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d protocol must be tcp or udp."), $index + 1);
	}

	$destination_port = trim((string)fwknop_array_get($rule, 'destination_port', ''));
	if (!fwknop_validate_port_or_alias($destination_port)) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d has an invalid destination port or port alias."), $index + 1);
	}

	$timeout = fwknop_array_get($rule, 'timeout_seconds', '');
	if (!fwknop_is_positive_int($timeout)) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d timeout must be a positive integer."), $index + 1);
	}

	$table = trim((string)fwknop_array_get($rule, 'table_name', ''));
	if ($table !== '' && !fwknop_is_valid_table_name($table)) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d has an invalid generated table name."), $index + 1);
	}

	if (!fwknop_is_base64_key(fwknop_array_get($rule, 'encryption_key', ''))) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d needs a valid base64 encryption key."), $index + 1);
	}
	if (!fwknop_is_base64_key(fwknop_array_get($rule, 'hmac_key', ''))) {
		$input_errors[] = sprintf(gettext("fwknop access rule %d needs a valid base64 HMAC key."), $index + 1);
	}
}

function fwknop_make_directories() {
	if (function_exists('safe_mkdir')) {
		safe_mkdir(FWKNOP_ETCDIR);
		safe_mkdir(FWKNOP_ACCESS_D_DIR);
	} else {
		if (!is_dir(FWKNOP_ETCDIR)) {
			mkdir(FWKNOP_ETCDIR, 0700, true);
		}
		if (!is_dir(FWKNOP_ACCESS_D_DIR)) {
			mkdir(FWKNOP_ACCESS_D_DIR, 0700, true);
		}
	}

	@chmod(FWKNOP_ETCDIR, 0700);
	@chmod(FWKNOP_ACCESS_D_DIR, 0700);
}

function fwknop_remove_generated_files() {
	if (function_exists('unlink_if_exists')) {
		unlink_if_exists(FWKNOP_FWKNOPD_CONF);
		unlink_if_exists(FWKNOP_ACCESS_CONF);
	} else {
		if (file_exists(FWKNOP_FWKNOPD_CONF)) {
			unlink(FWKNOP_FWKNOPD_CONF);
		}
		if (file_exists(FWKNOP_ACCESS_CONF)) {
			unlink(FWKNOP_ACCESS_CONF);
		}
	}

	if (is_dir(FWKNOP_ACCESS_D_DIR)) {
		foreach (glob(FWKNOP_ACCESS_D_DIR . '/*.conf') as $file) {
			if (function_exists('unlink_if_exists')) {
				unlink_if_exists($file);
			} else {
				unlink($file);
			}
		}
		@rmdir(FWKNOP_ACCESS_D_DIR);
	}
}

function fwknop_atomic_write($path, $content, $mode) {
	$directory = dirname($path);
	if (!is_dir($directory)) {
		fwknop_make_directories();
	}

	$temp = tempnam($directory, '.fwknop.');
	if ($temp === false) {
		throw new RuntimeException("Unable to create temporary file for {$path}");
	}

	if (file_put_contents($temp, $content, LOCK_EX) === false) {
		unlink($temp);
		throw new RuntimeException("Unable to write temporary file for {$path}");
	}

	@chown($temp, 'root');
	@chgrp($temp, 'wheel');
	chmod($temp, $mode);

	if (!rename($temp, $path)) {
		unlink($temp);
		throw new RuntimeException("Unable to activate generated file {$path}");
	}

	chmod($path, $mode);
}

function fwknop_get_access_rules() {
	$rules = config_get_path(FWKNOP_RULE_PATH, []);
	if (empty($rules)) {
		$rules = config_get_path(FWKNOP_LEGACY_CONFIG_RULE_PATH, []);
	}
	if (empty($rules)) {
		$rules = config_get_path(FWKNOP_LEGACY_PACKAGE_RULE_PATH, []);
	}
	if (empty($rules)) {
		$rules = config_get_path(FWKNOP_LEGACY_RULE_PATH, []);
	}

	return fwknop_normalize_rule_list($rules);
}

function fwknop_set_access_rules($rules) {
	config_set_path(FWKNOP_RULE_PATH, array('item' => array_values(fwknop_normalize_rule_list($rules))));
	if (function_exists('config_del_path')) {
		config_del_path(FWKNOP_LEGACY_CONFIG_RULE_PATH);
		config_del_path(FWKNOP_LEGACY_PACKAGE_RULE_PATH);
		config_del_path(FWKNOP_LEGACY_RULE_PATH);
	}
}

function fwknop_get_posted_access_rules($post) {
	if (!is_array($post)) {
		return [];
	}

	foreach (['accessrule', 'rule', 'rules'] as $key) {
		if (isset($post[$key])) {
			return fwknop_normalize_rule_list($post[$key]);
		}
	}

	if (isset($post['protocol']) || isset($post['destination_port']) ||
	    isset($post['encryption_key']) || isset($post['hmac_key'])) {
		return [$post];
	}

	return [];
}

function fwknop_normalize_rule_list($rules) {
	if (!is_array($rules)) {
		return [];
	}
	if (isset($rules['item']) && is_array($rules['item'])) {
		$rules = $rules['item'];
	}
	if (isset($rules['config']) && is_array($rules['config'])) {
		$rules = $rules['config'];
	}
	if (isset($rules['description']) || isset($rules['destination_port'])) {
		return [$rules];
	}

	$normalized = [];
	foreach ($rules as $rule) {
		if (is_array($rule)) {
			$normalized[] = $rule;
		}
	}

	return $normalized;
}

function fwknop_array_get($array, $path, $default = null) {
	if (function_exists('array_get_path')) {
		return array_get_path($array, $path, $default);
	}
	if (!is_array($array)) {
		return $default;
	}
	$parts = explode('/', $path);
	$value = $array;
	foreach ($parts as $part) {
		if (!is_array($value) || !array_key_exists($part, $value)) {
			return $default;
		}
		$value = $value[$part];
	}

	return $value;
}

function fwknop_is_enabled($value) {
	if (is_array($value)) {
		$value = fwknop_array_get($value, 'enabled', fwknop_array_get($value, 'enable', 'off'));
	}

	return in_array(strtolower((string)$value), ['1', 'on', 'yes', 'true', 'enabled'], true);
}

function fwknop_normalize_list($value) {
	if (is_array($value)) {
		$list = $value;
	} else {
		$list = explode(',', (string)$value);
	}

	$result = [];
	foreach ($list as $item) {
		$item = trim((string)$item);
		if ($item !== '') {
			$result[] = $item;
		}
	}

	return array_values(array_unique($result));
}

function fwknop_is_valid_interface($interface) {
	if (!preg_match('/^[A-Za-z0-9_.:-]+$/', (string)$interface)) {
		return false;
	}
	if (function_exists('get_real_interface')) {
		return get_real_interface($interface) !== '';
	}

	return true;
}

function fwknop_get_real_interfaces($interfaces) {
	$result = [];
	foreach ($interfaces as $interface) {
		if (!fwknop_is_valid_interface($interface)) {
			continue;
		}
		$result[] = function_exists('get_real_interface') ? get_real_interface($interface) : $interface;
	}

	return array_values(array_unique(array_filter($result)));
}

function fwknop_is_port($value) {
	if (function_exists('is_port')) {
		return is_port($value);
	}

	return ctype_digit((string)$value) && (int)$value >= 1 && (int)$value <= 65535;
}

function fwknop_is_positive_int($value) {
	if (function_exists('is_numericint')) {
		return is_numericint($value) && (int)$value > 0;
	}

	return ctype_digit((string)$value) && (int)$value > 0;
}

function fwknop_positive_int($value, $default) {
	return fwknop_is_positive_int($value) ? (int)$value : (int)$default;
}

function fwknop_normalize_log_level($value, $validate_only = false) {
	$map = [
		'quiet' => '0',
		'error' => '0',
		'warn' => '0',
		'warning' => '0',
		'notice' => '1',
		'info' => '1',
		'verbose' => '2',
		'debug' => '3'
	];
	$value = strtolower(trim((string)$value));
	if (isset($map[$value])) {
		return $validate_only ? true : $map[$value];
	}
	if (in_array($value, ['0', '1', '2', '3'], true)) {
		return $validate_only ? true : $value;
	}

	return $validate_only ? false : '0';
}

function fwknop_is_safe_config_value($value, $allow_empty = false) {
	$value = (string)$value;
	if ($allow_empty && $value === '') {
		return true;
	}

	return !preg_match('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', $value) &&
	    strpos($value, "\n") === false &&
	    strpos($value, "\r") === false &&
	    strpos($value, ';') === false;
}

function fwknop_is_safe_alias_name($value) {
	return is_string($value) && preg_match('/^[A-Za-z0-9_]+$/', $value);
}

function fwknop_is_alias_of_type($alias, $allowed_types) {
	if (!fwknop_is_safe_alias_name($alias)) {
		return false;
	}
	if (function_exists('is_alias') && !is_alias($alias)) {
		return false;
	}
	if (function_exists('alias_get_type')) {
		return in_array(alias_get_type($alias), $allowed_types, true);
	}

	return true;
}

function fwknop_validate_source_constraint($type, $value) {
	switch ($type) {
		case 'any':
			return $value === '';
		case 'ip':
			return function_exists('is_ipaddr') ? is_ipaddr($value) : filter_var($value, FILTER_VALIDATE_IP) !== false;
		case 'cidr':
			return function_exists('is_subnet') ? is_subnet($value) : fwknop_is_subnet($value);
		case 'alias':
			return fwknop_is_alias_of_type($value, ['host', 'network']);
	}

	return false;
}

function fwknop_validate_destination($type, $value) {
	switch ($type) {
		case 'firewall':
			return $value === '';
		case 'interface':
			return fwknop_is_valid_interface($value);
		case 'host':
			return (function_exists('is_ipaddr') ? is_ipaddr($value) : filter_var($value, FILTER_VALIDATE_IP) !== false) ||
			    (function_exists('is_subnet') ? is_subnet($value) : fwknop_is_subnet($value));
		case 'alias':
			return fwknop_is_alias_of_type($value, ['host', 'network']);
	}

	return false;
}

function fwknop_validate_port_or_alias($value) {
	if (fwknop_is_port($value)) {
		return true;
	}

	return fwknop_is_alias_of_type($value, ['port']);
}

function fwknop_is_subnet($value) {
	$parts = explode('/', (string)$value, 2);
	if (count($parts) !== 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false ||
	    !ctype_digit($parts[1])) {
		return false;
	}

	$max = strpos($parts[0], ':') === false ? 32 : 128;
	return (int)$parts[1] >= 0 && (int)$parts[1] <= $max;
}

function fwknop_is_base64_key($value) {
	$value = trim((string)$value);
	if (strlen($value) < 16 || !preg_match('/^[A-Za-z0-9+\/=]+$/', $value)) {
		return false;
	}

	return base64_decode($value, true) !== false;
}

function fwknop_is_valid_table_name($table) {
	return is_string($table) && preg_match('/^fwknop_[A-Za-z0-9_]+$/', $table);
}

function fwknop_table_name_for_rule($rule, $index) {
	$table = trim((string)fwknop_array_get($rule, 'table_name', ''));
	if (fwknop_is_valid_table_name($table)) {
		return $table;
	}

	$rule_id = trim((string)fwknop_array_get($rule, 'ruleid', fwknop_array_get($rule, 'id', '')));
	$rule_id = preg_replace('/[^A-Za-z0-9_]/', '_', $rule_id);
	if ($rule_id === '') {
		$rule_id = 'rule' . ($index + 1);
	}

	return 'fwknop_' . $rule_id;
}

function fwknop_open_ports_for_rule($rule, $protocol) {
	$port = trim((string)fwknop_array_get($rule, 'destination_port', ''));
	if (fwknop_is_port($port)) {
		return ["{$protocol}/{$port}"];
	}

	if (!fwknop_is_alias_of_type($port, ['port']) || !function_exists('filter_expand_alias')) {
		return [];
	}

	$ports = [];
	foreach (preg_split('/[\s,]+/', trim(filter_expand_alias($port))) as $expanded_port) {
		if (fwknop_is_port($expanded_port)) {
			$ports[] = "{$protocol}/{$expanded_port}";
		}
	}

	return array_values(array_unique($ports));
}

function fwknop_source_for_rule($rule) {
	$type = strtolower((string)fwknop_array_get($rule, 'source_constraint_type', 'any'));
	$value = trim((string)fwknop_array_get($rule, 'source_constraint_value', ''));
	if ($type === 'any') {
		return 'ANY';
	}
	if ($type === 'alias' && function_exists('filter_expand_alias')) {
		$expanded = trim(filter_expand_alias($value));
		return $expanded !== '' ? implode(',', preg_split('/[\s,]+/', $expanded)) : 'ANY';
	}

	return fwknop_safe_directive_value($value);
}

function fwknop_destination_for_rule($rule) {
	$type = strtolower((string)fwknop_array_get($rule, 'destination_type', 'firewall'));
	$value = trim((string)fwknop_array_get($rule, 'destination_value', ''));
	if ($type === 'firewall' || $value === '') {
		return '';
	}
	if ($type === 'interface') {
		if (!fwknop_is_valid_interface($value)) {
			return '';
		}

		$interface_ip = function_exists('get_interface_ip') ? get_interface_ip($value) : '';
		return $interface_ip !== '' ? fwknop_safe_directive_value($interface_ip) : '';
	}
	if ($type === 'alias' && function_exists('filter_expand_alias')) {
		$expanded = trim(filter_expand_alias($value));
		return $expanded !== '' ? implode(',', preg_split('/[\s,]+/', $expanded)) : '';
	}

	return fwknop_safe_directive_value($value);
}

function fwknop_safe_directive_value($value) {
	return str_replace([';', "\r", "\n"], '', trim((string)$value));
}

function fwknop_comment_value($value) {
	$value = fwknop_safe_directive_value($value);
	return $value !== '' ? $value : 'fwknop access rule';
}

function fwknop_generate_package_rules($type = "filter") {
	if (!in_array($type, ['filter', 'rule'], true)) {
		return '';
	}

	$settings = fwknop_get_settings();
	if (!fwknop_is_enabled($settings) ||
	    !fwknop_is_enabled(fwknop_array_get($settings, 'managed_pf_table_mode', 'on'))) {
		return '';
	}

	$interfaces = fwknop_pf_interfaces($settings);
	if (empty($interfaces)) {
		fwknop_log_warning('Cannot generate fwknop package rules: no valid listen interfaces are configured.');
		return '';
	}

	$rules = '';
	$declared_tables = [];
	foreach (fwknop_get_access_rules() as $index => $rule) {
		if (!fwknop_is_enabled(fwknop_array_get($rule, 'enabled', fwknop_array_get($rule, 'enable', 'on')))) {
			continue;
		}

		$table = fwknop_table_name_for_rule($rule, $index);
		if (!fwknop_is_valid_table_name($table)) {
			fwknop_log_warning("Skipping fwknop rule with invalid table name: {$table}");
			continue;
		}

		$protocol = strtolower((string)fwknop_array_get($rule, 'protocol', ''));
		if (!in_array($protocol, ['tcp', 'udp'], true)) {
			continue;
		}

		$port = fwknop_pf_port_for_rule($rule);
		if ($port === '') {
			continue;
		}

		if (!isset($declared_tables[$table])) {
			$rules .= "table <{$table}> persist\n";
			$declared_tables[$table] = true;
		}

		$description = fwknop_comment_value((string)fwknop_array_get($rule, 'description', "Rule {$index}"));
		$label = fwknop_pf_label($description);
		foreach ($interfaces as $interface) {
			$destination = fwknop_pf_destination_for_rule($rule, $interface['real']);
			if ($destination === '') {
				continue;
			}

			fwknop_warn_if_service_exposed($interface['friendly'], $rule, $protocol, $port, $description);
			$rules .= "pass in quick on {$interface['real']} proto {$protocol} from <{$table}> to {$destination} port {$port} keep state label \"fwknop: {$label}\"\n";
		}
	}

	return $rules;
}

function fwknop_write_table_helper() {
	$directory = dirname(FWKNOP_TABLE_HELPER);
	if (!is_dir($directory)) {
		if (function_exists('safe_mkdir')) {
			safe_mkdir($directory);
		} else {
			mkdir($directory, 0755, true);
		}
	}

	$temp = tempnam($directory, '.fwknop-table.');
	if ($temp === false) {
		throw new RuntimeException('Unable to create temporary fwknop table helper.');
	}

	if (file_put_contents($temp, fwknop_table_helper_source(), LOCK_EX) === false) {
		unlink($temp);
		throw new RuntimeException('Unable to write temporary fwknop table helper.');
	}

	@chown($temp, 'root');
	@chgrp($temp, 'wheel');
	chmod($temp, 0755);

	if (!rename($temp, FWKNOP_TABLE_HELPER)) {
		unlink($temp);
		throw new RuntimeException('Unable to activate fwknop table helper.');
	}

	chmod(FWKNOP_TABLE_HELPER, 0755);
	return FWKNOP_TABLE_HELPER;
}

function fwknop_pf_interfaces($settings) {
	$result = [];
	foreach (fwknop_normalize_list(fwknop_array_get($settings, 'listen_interfaces', '')) as $friendly) {
		if (!fwknop_is_valid_interface($friendly)) {
			continue;
		}
		$real = function_exists('get_real_interface') ? get_real_interface($friendly) : $friendly;
		if ($real === '' || !preg_match('/^[A-Za-z0-9_.:-]+$/', $real)) {
			continue;
		}
		$result[] = [
			'friendly' => $friendly,
			'real' => $real
		];
	}

	return $result;
}

function fwknop_pf_port_for_rule($rule) {
	$port = trim((string)fwknop_array_get($rule, 'destination_port', ''));
	if (fwknop_is_port($port)) {
		return $port;
	}
	if (fwknop_is_alias_of_type($port, ['port'])) {
		return '$' . $port;
	}

	return '';
}

function fwknop_pf_destination_for_rule($rule, $real_interface) {
	$type = strtolower((string)fwknop_array_get($rule, 'destination_type', 'firewall'));
	$value = trim((string)fwknop_array_get($rule, 'destination_value', ''));

	switch ($type) {
		case 'firewall':
			return "({$real_interface})";
		case 'interface':
			if (!fwknop_is_valid_interface($value)) {
				return '';
			}
			$destination_interface = function_exists('get_real_interface') ? get_real_interface($value) : $value;
			return $destination_interface !== '' ? "({$destination_interface})" : '';
		case 'host':
			if ((function_exists('is_ipaddr') && is_ipaddr($value)) ||
			    (function_exists('is_subnet') && is_subnet($value)) ||
			    filter_var($value, FILTER_VALIDATE_IP) !== false ||
			    fwknop_is_subnet($value)) {
				return fwknop_safe_directive_value($value);
			}
			return '';
		case 'alias':
			return fwknop_is_alias_of_type($value, ['host', 'network']) ? '$' . $value : '';
	}

	return '';
}

function fwknop_pf_label($description) {
	return str_replace(['\\', '"'], ['\\\\', '\"'], fwknop_comment_value($description));
}

function fwknop_warn_if_service_exposed($interface, $fwknop_rule, $protocol, $port, $description) {
	foreach (fwknop_find_exposing_firewall_rules($interface, $fwknop_rule, $protocol, $port) as $rule_descr) {
		fwknop_log_warning("fwknop protected service '{$description}' may already be exposed by normal firewall rule '{$rule_descr}'.");
	}
}

function fwknop_find_exposing_firewall_rules($interface, $fwknop_rule, $protocol, $port) {
	$matches = [];
	$filter_rules = config_get_path('filter/rule', []);
	if (!is_array($filter_rules)) {
		return $matches;
	}

	foreach ($filter_rules as $rule) {
		if (!is_array($rule) || fwknop_is_enabled(fwknop_array_get($rule, 'disabled', 'off'))) {
			continue;
		}
		if (strtolower((string)fwknop_array_get($rule, 'type', 'pass')) !== 'pass') {
			continue;
		}
		if (!fwknop_filter_rule_matches_interface($rule, $interface) ||
		    !fwknop_filter_rule_matches_protocol($rule, $protocol) ||
		    !fwknop_filter_rule_matches_port($rule, $port) ||
		    !fwknop_filter_rule_matches_destination($rule, $fwknop_rule)) {
			continue;
		}

		$matches[] = fwknop_comment_value((string)fwknop_array_get($rule, 'descr', 'unnamed rule'));
	}

	return $matches;
}

function fwknop_filter_rule_matches_interface($rule, $interface) {
	$rule_interface = fwknop_array_get($rule, 'interface', '');
	if ($rule_interface === '' || $rule_interface === 'any') {
		return true;
	}

	return in_array($interface, fwknop_normalize_list($rule_interface), true);
}

function fwknop_filter_rule_matches_protocol($rule, $protocol) {
	$rule_protocol = strtolower((string)fwknop_array_get($rule, 'protocol', ''));
	return $rule_protocol === '' || $rule_protocol === 'any' || $rule_protocol === $protocol;
}

function fwknop_filter_rule_matches_port($rule, $port) {
	$destination = fwknop_array_get($rule, 'destination', []);
	$rule_port = trim((string)fwknop_array_get($destination, 'port', ''));
	if ($rule_port === '') {
		return true;
	}
	if ($rule_port === $port) {
		return true;
	}
	if ($port !== '' && $port[0] === '$') {
		return '$' . $rule_port === $port;
	}

	return false;
}

function fwknop_filter_rule_matches_destination($rule, $fwknop_rule) {
	$destination = fwknop_array_get($rule, 'destination', []);
	$rule_address = trim((string)fwknop_array_get($destination, 'address', ''));
	if ($rule_address === '' || $rule_address === 'any') {
		return true;
	}

	$fwknop_type = strtolower((string)fwknop_array_get($fwknop_rule, 'destination_type', 'firewall'));
	$fwknop_value = trim((string)fwknop_array_get($fwknop_rule, 'destination_value', ''));
	if ($fwknop_type === 'firewall') {
		return in_array($rule_address, ['self', 'This Firewall'], true);
	}

	return $rule_address === $fwknop_value;
}

function fwknop_log_warning($message) {
	if (function_exists('logger')) {
		logger(LOG_WARNING, function_exists('localize_text') ? localize_text($message) : $message, LOG_PREFIX_PKG_FWKNOP);
	}
}

function fwknop_table_helper_source() {
	return <<<'PHP'
#!/usr/local/bin/php
<?php

const FWKNOP_HELPER_PFCTL = '/sbin/pfctl';
const FWKNOP_HELPER_LOGGER = '/usr/bin/logger';
const FWKNOP_HELPER_TAG = 'pfsense-fwknop-table';

function fwknop_helper_fail($message) {
	fwknop_helper_log('authpriv.warning', 'reject: ' . $message);
	fwrite(STDERR, $message . PHP_EOL);
	exit(1);
}

function fwknop_helper_log($priority, $message) {
	$command = FWKNOP_HELPER_LOGGER .
	    ' -p ' . escapeshellarg($priority) .
	    ' -t ' . escapeshellarg(FWKNOP_HELPER_TAG) .
	    ' ' . escapeshellarg($message);
	exec($command, $output, $retval);
}

function fwknop_helper_valid_source($source) {
	if (filter_var($source, FILTER_VALIDATE_IP) !== false) {
		return true;
	}

	$parts = explode('/', $source, 2);
	if (count($parts) !== 2 ||
	    filter_var($parts[0], FILTER_VALIDATE_IP) === false ||
	    !ctype_digit($parts[1])) {
		return false;
	}

	$max_prefix = strpos($parts[0], ':') === false ? 32 : 128;
	return (int)$parts[1] >= 0 && (int)$parts[1] <= $max_prefix;
}

function fwknop_helper_valid_port($port) {
	return ctype_digit($port) && (int)$port >= 1 && (int)$port <= 65535;
}

if ($argc < 6) {
	fwknop_helper_fail('usage: pfsense-fwknop-table open|close table source tcp|udp port [timeout]');
}

$action = $argv[1];
$table = $argv[2];
$source = $argv[3];
$protocol = strtolower($argv[4]);
$port = $argv[5];
$timeout = $argv[6] ?? null;

if (!in_array($action, ['open', 'close'], true)) {
	fwknop_helper_fail('invalid action');
}
if (!preg_match('/^fwknop_[A-Za-z0-9_]+$/', $table)) {
	fwknop_helper_fail('invalid table name');
}
if (!fwknop_helper_valid_source($source)) {
	fwknop_helper_fail('invalid source address');
}
if (!in_array($protocol, ['tcp', 'udp'], true)) {
	fwknop_helper_fail('invalid protocol');
}
if (!fwknop_helper_valid_port($port)) {
	fwknop_helper_fail('invalid port');
}
if ($action === 'open' && ($timeout === null || !ctype_digit($timeout) || (int)$timeout < 1)) {
	fwknop_helper_fail('invalid timeout');
}
if ($action === 'close' && $timeout !== null) {
	fwknop_helper_fail('unexpected close timeout');
}

$pf_action = $action === 'open' ? 'add' : 'delete';
$command = FWKNOP_HELPER_PFCTL .
    ' -t ' . escapeshellarg($table) .
    ' -T ' . $pf_action .
    ' ' . escapeshellarg($source);
exec($command, $output, $retval);

if ($retval !== 0) {
	fwknop_helper_log('authpriv.warning', "{$action} failed table={$table} source={$source} proto={$protocol} port={$port}");
	exit($retval);
}

fwknop_helper_log('authpriv.notice', "{$action} table={$table} source={$source} proto={$protocol} port={$port}");
exit(0);
PHP;
}
