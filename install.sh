#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="chimera"
APP_BIN="chimera_server_app"
CLI_BIN="chimera_cli"
APP_ALIAS="chimera-server"
CLI_ALIAS="chimera-cli"

GITHUB_REPO="MFSGA/Chimera_Server"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/usr/local/etc/${SERVICE_NAME}"
SHARE_DIR="/usr/local/share/${SERVICE_NAME}"
LIB_DIR="/usr/local/lib/${SERVICE_NAME}"
BACKUP_DIR="${LIB_DIR}/backup"
LOG_DIR="/var/log/${SERVICE_NAME}"

ACTION="install"
BUILD_DIR=""
CONFIG_SOURCE=""
SERVICE_MANAGER="auto"
ENABLE_SERVICE=1
START_SERVICE=0
BUILD_IF_MISSING=1
ONLINE_UPDATE=0
RELEASE_VERSION=""
UPDATE_GEO=0
ROLLBACK_ON_FAILURE=1

usage() {
    cat <<EOF
Usage: $0 [install|update|rollback|uninstall|status] [options]

Install Chimera Server binaries and register them with a common Linux service manager.

Options:
  --from DIR             Directory containing ${APP_BIN} and optionally ${CLI_BIN}
                         (default: ./target/release)
  --latest               Download and install the latest GitHub Release binary
  --version VERSION      Download and install a specific GitHub Release tag, e.g. v0.3.2
  --repo OWNER/REPO      GitHub repository used by --latest/--version
                         (default: ${GITHUB_REPO})
  --update-geo           Download latest geoip.dat and geosite.dat from v2fly/domain-list
                         release sources
  --config FILE          Initial config copied to ${CONFIG_DIR}/config.json5 when absent
                         (default: ./config.json5 when present)
  --manager NAME         auto, systemd, openrc, runit, none (default: auto)
  --no-build             Do not run cargo build when local binaries are missing
  --no-enable            Install service files but do not enable them
  --no-rollback          Do not restore the previous binary if service restart fails
  --start                Start or restart the service after install/update
  -h, --help             Show this help

Examples:
  sudo $0
  sudo $0 update --latest --start
  sudo $0 update --version v0.3.2 --update-geo --start
  sudo $0 rollback --start
  sudo $0 uninstall
EOF
}

die() {
    echo "error: $*" >&2
    exit 1
}

warn() {
    echo "warning: $*" >&2
}

info() {
    echo "==> $*"
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "this installer must run as root"
    fi
}

repo_root() {
    local script_dir
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    printf '%s\n' "${script_dir}"
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            install|update|rollback|uninstall|status)
                ACTION="$1"
                ;;
            --from)
                shift
                [ "$#" -gt 0 ] || die "--from requires a directory"
                BUILD_DIR="$1"
                ;;
            --latest)
                ONLINE_UPDATE=1
                RELEASE_VERSION="latest"
                ;;
            --version)
                shift
                [ "$#" -gt 0 ] || die "--version requires a tag"
                ONLINE_UPDATE=1
                RELEASE_VERSION="$1"
                ;;
            --repo)
                shift
                [ "$#" -gt 0 ] || die "--repo requires OWNER/REPO"
                GITHUB_REPO="$1"
                ;;
            --update-geo)
                UPDATE_GEO=1
                ;;
            --config)
                shift
                [ "$#" -gt 0 ] || die "--config requires a file"
                CONFIG_SOURCE="$1"
                ;;
            --manager)
                shift
                [ "$#" -gt 0 ] || die "--manager requires a value"
                SERVICE_MANAGER="$1"
                ;;
            --no-build)
                BUILD_IF_MISSING=0
                ;;
            --no-enable)
                ENABLE_SERVICE=0
                ;;
            --no-rollback)
                ROLLBACK_ON_FAILURE=0
                ;;
            --start)
                START_SERVICE=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
        shift
    done
}

detect_service_manager() {
    if [ "${SERVICE_MANAGER}" != "auto" ]; then
        printf '%s\n' "${SERVICE_MANAGER}"
        return
    fi

    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        printf '%s\n' "systemd"
    elif command -v rc-service >/dev/null 2>&1 && [ -d /etc/init.d ]; then
        printf '%s\n' "openrc"
    elif command -v sv >/dev/null 2>&1 && [ -d /etc/sv ]; then
        printf '%s\n' "runit"
    else
        printf '%s\n' "none"
    fi
}

download_file() {
    local url output
    url="$1"
    output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fL --retry 3 --connect-timeout 20 -o "${output}" "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "${output}" "${url}"
    else
        die "curl or wget is required for online updates"
    fi
}

http_effective_url() {
    local url
    url="$1"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSLI -o /dev/null -w '%{url_effective}' "${url}"
    elif command -v wget >/dev/null 2>&1; then
        wget --max-redirect=10 --server-response --spider "${url}" 2>&1 \
            | awk '/^  Location: / { value=$2 } END { gsub(/\r/, "", value); print value }'
    else
        die "curl or wget is required for online updates"
    fi
}

latest_release_tag() {
    local latest_url effective tag
    latest_url="https://github.com/${GITHUB_REPO}/releases/latest"
    effective="$(http_effective_url "${latest_url}")"
    tag="${effective##*/}"

    [ -n "${tag}" ] && [ "${tag}" != "latest" ] || die "could not resolve latest release tag"
    printf '%s\n' "${tag}"
}

normalize_arch() {
    local machine
    machine="$(uname -m)"

    case "${machine}" in
        x86_64|amd64)
            printf '%s\n' "x86_64"
            ;;
        *)
            die "unsupported CPU architecture for online release asset: ${machine}"
            ;;
    esac
}

release_asset_name() {
    local version arch
    version="$1"
    arch="$(normalize_arch)"

    printf '%s-%s-linux-%s\n' "${APP_BIN}" "${version}" "${arch}"
}

resolve_release_version() {
    if [ -z "${RELEASE_VERSION}" ] || [ "${RELEASE_VERSION}" = "latest" ]; then
        latest_release_tag
    else
        printf '%s\n' "${RELEASE_VERSION}"
    fi
}

verify_sha256_if_available() {
    local file checksum_file checksum_url
    file="$1"
    checksum_file="${file}.sha256"
    checksum_url="$2"

    if ! command -v sha256sum >/dev/null 2>&1; then
        warn "sha256sum not found; skipping checksum verification"
        return
    fi

    if download_file "${checksum_url}" "${checksum_file}"; then
        (
            cd "$(dirname "${file}")"
            sha256sum -c "$(basename "${checksum_file}")"
        )
    else
        warn "checksum file not found; install will continue without checksum verification"
    fi
}

download_release_binary() {
    local version asset url tmp_dir output checksum_url
    version="$(resolve_release_version)"
    asset="$(release_asset_name "${version}")"
    url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${asset}"
    checksum_url="${url}.sha256"
    tmp_dir="$(mktemp -d)"
    output="${tmp_dir}/${asset}"

    info "downloading ${GITHUB_REPO} ${version} (${asset})"
    download_file "${url}" "${output}"
    verify_sha256_if_available "${output}" "${checksum_url}"
    mv "${output}" "${tmp_dir}/${APP_BIN}"
    chmod 0755 "${tmp_dir}/${APP_BIN}"

    BUILD_DIR="${tmp_dir}"
}

download_geo_files() {
    local tmp_dir geoip geosite
    tmp_dir="$(mktemp -d)"
    geoip="${tmp_dir}/geoip.dat"
    geosite="${tmp_dir}/geosite.dat"

    info "downloading geoip.dat"
    download_file "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" "${geoip}"
    info "downloading geosite.dat"
    download_file "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" "${geosite}"

    install -d -m 0755 "${SHARE_DIR}"
    install -m 0644 "${geoip}" "${SHARE_DIR}/geoip.dat"
    install -m 0644 "${geosite}" "${SHARE_DIR}/geosite.dat"
}

ensure_build_dir() {
    local root
    root="$(repo_root)"

    if [ "${ONLINE_UPDATE}" -eq 1 ]; then
        download_release_binary
        return
    fi

    if [ -z "${BUILD_DIR}" ]; then
        BUILD_DIR="${root}/target/release"
    elif [ "${BUILD_DIR#/}" = "${BUILD_DIR}" ]; then
        BUILD_DIR="${root}/${BUILD_DIR}"
    fi

    if [ ! -x "${BUILD_DIR}/${APP_BIN}" ] && [ "${BUILD_IF_MISSING}" -eq 1 ]; then
        command -v cargo >/dev/null 2>&1 || die "${BUILD_DIR}/${APP_BIN} not found and cargo is not installed"
        info "building release binaries"
        cargo build --release --all-features --manifest-path "${root}/Cargo.toml"
    fi

    [ -x "${BUILD_DIR}/${APP_BIN}" ] || die "missing executable: ${BUILD_DIR}/${APP_BIN}"
}

backup_current_binary() {
    local backup_path timestamp

    if [ ! -x "${INSTALL_DIR}/${APP_BIN}" ]; then
        return
    fi

    timestamp="$(date -u +%Y%m%d%H%M%S)"
    install -d -m 0755 "${BACKUP_DIR}"
    backup_path="${BACKUP_DIR}/${APP_BIN}.${timestamp}"
    cp -p "${INSTALL_DIR}/${APP_BIN}" "${backup_path}"
    ln -sfn "${backup_path}" "${BACKUP_DIR}/${APP_BIN}.previous"
    info "backed up current binary to ${backup_path}"
}

restore_previous_binary() {
    local previous
    previous="${BACKUP_DIR}/${APP_BIN}.previous"

    if [ ! -e "${previous}" ]; then
        die "no rollback binary found at ${previous}"
    fi

    install -m 0755 "$(readlink -f "${previous}")" "${INSTALL_DIR}/${APP_BIN}"
    ln -sfn "${INSTALL_DIR}/${APP_BIN}" "${INSTALL_DIR}/${APP_ALIAS}"
    info "restored previous binary"
}

install_files() {
    local root config_target
    root="$(repo_root)"
    config_target="${CONFIG_DIR}/config.json5"

    install -d -m 0755 "${INSTALL_DIR}" "${CONFIG_DIR}" "${SHARE_DIR}" "${LIB_DIR}" "${LOG_DIR}"

    backup_current_binary
    install -m 0755 "${BUILD_DIR}/${APP_BIN}" "${INSTALL_DIR}/${APP_BIN}"
    ln -sfn "${INSTALL_DIR}/${APP_BIN}" "${INSTALL_DIR}/${APP_ALIAS}"

    if [ -x "${BUILD_DIR}/${CLI_BIN}" ]; then
        install -m 0755 "${BUILD_DIR}/${CLI_BIN}" "${INSTALL_DIR}/${CLI_BIN}"
        ln -sfn "${INSTALL_DIR}/${CLI_BIN}" "${INSTALL_DIR}/${CLI_ALIAS}"
    fi

    if [ -z "${CONFIG_SOURCE}" ] && [ -f "${root}/config.json5" ]; then
        CONFIG_SOURCE="${root}/config.json5"
    fi

    if [ -n "${CONFIG_SOURCE}" ]; then
        if [ "${CONFIG_SOURCE#/}" = "${CONFIG_SOURCE}" ]; then
            CONFIG_SOURCE="${root}/${CONFIG_SOURCE}"
        fi
        [ -f "${CONFIG_SOURCE}" ] || die "config file not found: ${CONFIG_SOURCE}"
        if [ ! -f "${config_target}" ]; then
            install -m 0644 "${CONFIG_SOURCE}" "${config_target}"
            info "installed initial config to ${config_target}"
        else
            info "keeping existing config at ${config_target}"
        fi
    fi

    for data_file in geoip.dat geosite.dat; do
        if [ -f "${root}/${data_file}" ]; then
            install -m 0644 "${root}/${data_file}" "${SHARE_DIR}/${data_file}"
        fi
    done
}

write_systemd_service() {
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Chimera Server
Documentation=https://github.com/mfsga/Chimera_Server
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
ExecStart=${INSTALL_DIR}/${APP_ALIAS} ${CONFIG_DIR} --config config.json5
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
WorkingDirectory=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    if [ "${ENABLE_SERVICE}" -eq 1 ]; then
        systemctl enable "${SERVICE_NAME}.service"
    fi
}

write_openrc_service() {
    cat > "/etc/init.d/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run
name="Chimera Server"
description="Chimera Server"
command="${INSTALL_DIR}/${APP_ALIAS}"
command_args="${CONFIG_DIR} --config config.json5"
command_background="yes"
directory="${CONFIG_DIR}"
pidfile="/run/${SERVICE_NAME}.pid"
output_log="${LOG_DIR}/${SERVICE_NAME}.log"
error_log="${LOG_DIR}/${SERVICE_NAME}.err"

depend() {
    need net
    after firewall
}
EOF
    chmod 0755 "/etc/init.d/${SERVICE_NAME}"

    if [ "${ENABLE_SERVICE}" -eq 1 ]; then
        rc-update add "${SERVICE_NAME}" default
    fi
}

write_runit_service() {
    install -d -m 0755 "/etc/sv/${SERVICE_NAME}/log"
    cat > "/etc/sv/${SERVICE_NAME}/run" <<EOF
#!/bin/sh
exec 2>&1
cd "${CONFIG_DIR}" || exit 1
exec "${INSTALL_DIR}/${APP_ALIAS}" "${CONFIG_DIR}" --config config.json5
EOF
    cat > "/etc/sv/${SERVICE_NAME}/log/run" <<EOF
#!/bin/sh
exec svlogd -tt "${LOG_DIR}"
EOF
    chmod 0755 "/etc/sv/${SERVICE_NAME}/run" "/etc/sv/${SERVICE_NAME}/log/run"

    if [ "${ENABLE_SERVICE}" -eq 1 ]; then
        if [ -d /var/service ]; then
            ln -sfn "/etc/sv/${SERVICE_NAME}" "/var/service/${SERVICE_NAME}"
        elif [ -d /service ]; then
            ln -sfn "/etc/sv/${SERVICE_NAME}" "/service/${SERVICE_NAME}"
        fi
    fi
}

install_service() {
    local manager
    manager="$(detect_service_manager)"

    case "${manager}" in
        systemd)
            info "installing systemd service"
            write_systemd_service
            ;;
        openrc)
            info "installing OpenRC service"
            write_openrc_service
            ;;
        runit)
            info "installing runit service"
            write_runit_service
            ;;
        none)
            info "no supported service manager detected; binaries were installed only"
            ;;
        *)
            die "unsupported service manager: ${manager}"
            ;;
    esac
}

restart_service() {
    local manager
    manager="$(detect_service_manager)"

    case "${manager}" in
        systemd)
            systemctl restart "${SERVICE_NAME}.service"
            ;;
        openrc)
            rc-service "${SERVICE_NAME}" restart
            ;;
        runit)
            sv restart "${SERVICE_NAME}"
            ;;
        none)
            info "no supported service manager detected; skipping restart"
            ;;
        *)
            die "unsupported service manager: ${manager}"
            ;;
    esac
}

start_or_restart_service() {
    if [ "${START_SERVICE}" -ne 1 ]; then
        return
    fi

    if restart_service; then
        return
    fi

    if [ "${ROLLBACK_ON_FAILURE}" -eq 1 ]; then
        warn "service restart failed; rolling back binary"
        restore_previous_binary
        restart_service
        return
    fi

    return 1
}

validate_config() {
    if [ -f "${CONFIG_DIR}/config.json5" ]; then
        if ! "${INSTALL_DIR}/${APP_ALIAS}" "${CONFIG_DIR}" --config config.json5 --check; then
            warn "installed config did not pass validation; edit ${CONFIG_DIR}/config.json5 before starting the service"
        fi
    fi
}

uninstall_service() {
    local manager
    manager="$(detect_service_manager)"

    case "${manager}" in
        systemd)
            systemctl disable --now "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            systemctl daemon-reload
            ;;
        openrc)
            rc-service "${SERVICE_NAME}" stop >/dev/null 2>&1 || true
            rc-update del "${SERVICE_NAME}" default >/dev/null 2>&1 || true
            rm -f "/etc/init.d/${SERVICE_NAME}"
            ;;
        runit)
            sv down "${SERVICE_NAME}" >/dev/null 2>&1 || true
            rm -f "/var/service/${SERVICE_NAME}" "/service/${SERVICE_NAME}"
            rm -rf "/etc/sv/${SERVICE_NAME}"
            ;;
        none)
            ;;
        *)
            die "unsupported service manager: ${manager}"
            ;;
    esac
}

uninstall_files() {
    rm -f \
        "${INSTALL_DIR}/${APP_BIN}" \
        "${INSTALL_DIR}/${CLI_BIN}" \
        "${INSTALL_DIR}/${APP_ALIAS}" \
        "${INSTALL_DIR}/${CLI_ALIAS}"

    info "kept ${CONFIG_DIR}, ${SHARE_DIR}, ${LIB_DIR}, and ${LOG_DIR}"
}

show_status() {
    local manager
    manager="$(detect_service_manager)"

    echo "service manager: ${manager}"
    case "${manager}" in
        systemd)
            systemctl status "${SERVICE_NAME}.service" --no-pager || true
            ;;
        openrc)
            rc-service "${SERVICE_NAME}" status || true
            ;;
        runit)
            sv status "${SERVICE_NAME}" || true
            ;;
        none)
            [ -x "${INSTALL_DIR}/${APP_ALIAS}" ] && "${INSTALL_DIR}/${APP_ALIAS}" --help || true
            ;;
    esac
}

main() {
    parse_args "$@"
    require_root

    case "${ACTION}" in
        install|update)
            ensure_build_dir
            install_files
            if [ "${UPDATE_GEO}" -eq 1 ]; then
                download_geo_files
            fi
            validate_config
            install_service
            start_or_restart_service
            info "installed ${APP_ALIAS} to ${INSTALL_DIR}"
            ;;
        rollback)
            restore_previous_binary
            start_or_restart_service
            ;;
        uninstall)
            uninstall_service
            uninstall_files
            ;;
        status)
            show_status
            ;;
        *)
            die "unsupported action: ${ACTION}"
            ;;
    esac
}

main "$@"
