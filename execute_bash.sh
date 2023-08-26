#!/bin/sh
set -e
    
# that all scripts have "set -e" at the top of the bash file!
scripts/xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_logon_fail_delay.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed_sha512.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_dcredit.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_difok.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_lcredit.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_maxclassrepeat.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_ocredit.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_password_auth.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_system_auth.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_ucredit.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_password_pam_unix_remember.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_interval.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_umask_etc_csh_cshrc.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs.sh && \
scripts/xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile.sh && \
scripts/xccdf_org.ssgproject.content_rule_banner_etc_issue.sh && \
scripts/xccdf_org.ssgproject.content_rule_package_crypto-policies_installed.sh && \
scripts/xccdf_org.ssgproject.content_rule_configure_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_configure_kerberos_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_configure_openssl_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_configure_gnutls_tls_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_openssh_conf_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_harden_sshd_ciphers_opensshserver_conf_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_harden_sshd_macs_openssh_conf_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_harden_sshd_macs_opensshserver_conf_crypto_policy.sh && \
scripts/xccdf_org.ssgproject.content_rule_configure_usbguard_auditbackend.sh && \
scripts/xccdf_org.ssgproject.content_rule_coredump_disable_backtraces.sh && \
scripts/xccdf_org.ssgproject.content_rule_coredump_disable_storage.sh && \
scripts/xccdf_org.ssgproject.content_rule_disable_ctrlaltdel_burstaction.sh && \
scripts/xccdf_org.ssgproject.content_rule_disable_users_coredumps.sh && \
scripts/xccdf_org.ssgproject.content_rule_display_login_attempts.sh && \
scripts/xccdf_org.ssgproject.content_rule_ensure_gpgcheck_local_packages.sh && \
scripts/xccdf_org.ssgproject.content_rule_file_groupowner_var_log_messages.sh && \
scripts/xccdf_org.ssgproject.content_rule_file_groupownership_system_commands_dirs.sh && \
scripts/xccdf_org.ssgproject.content_rule_file_owner_var_log_messages.sh && \
scripts/xccdf_org.ssgproject.content_rule_network_configure_name_resolution.sh && \
scripts/xccdf_org.ssgproject.content_rule_no_empty_passwords.sh && \
scripts/xccdf_org.ssgproject.content_rule_openssl_use_strong_entropy.sh && \
scripts/xccdf_org.ssgproject.content_rule_package_iptables_installed.sh && \
# rng-tools not available in ubi
scripts/xccdf_org.ssgproject.content_rule_package_rng-tools_installed.sh && \
scripts/xccdf_org.ssgproject.content_rule_package_sudo_installed.sh && \
scripts/xccdf_org.ssgproject.content_rule_package_usbguard_installed.sh && \
scripts/xccdf_org.ssgproject.content_rule_sudo_require_reauthentication.sh && \
scripts/xccdf_org.ssgproject.content_rule_sudoers_validate_passwd.sh