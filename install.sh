#!/usr/bin/env bash
# mtdd installer, updater, and interactive management launcher.
#
# Modes:
#   - fresh system + installer flags  -> install or update the service;
#   - installed system, no arguments  -> interactive management menu;
#   - management subcommand           -> non-interactive management action.
set -Eeuo pipefail
umask 077

readonly MTDD_BIN=/usr/local/bin/mtdd
readonly MTDD_CTL=/usr/local/bin/mtdd-ctl
readonly MTDD_CONF=/etc/mtdd/config.json
readonly MTDD_CREDS=/etc/mtdd/credentials.env
readonly MTDD_STATE=/var/lib/mtdd
readonly MTDD_UNIT=/etc/systemd/system/mtdd.service
readonly MTDD_SERVICE=mtdd.service

repo=${MTDD_REPOSITORY:-ugDeDe/mtdd}
channel=main
channel_set=0
domain=
ad_tag=
proxy_port=443
port_set=0
public_host=
public_port=
user_name=admin
user_set=0
output=/usr/local/bin/mtdd
base_url=
binary_only=0

command=
cargs=()
yes_flag=0

bold= cyan= green= yellow= red= reset=
if [[ -t 1 && ${TERM:-dumb} != dumb && ! ${NO_COLOR+x} ]]; then
    bold=$'\033[1m'; cyan=$'\033[36m'; green=$'\033[32m'
    yellow=$'\033[33m'; red=$'\033[31m'; reset=$'\033[0m'
fi
line() { printf '  %s%s%s\n' "$cyan" '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━' "$reset"; }
step() { printf '  %s→%s %s\n' "$cyan" "$reset" "$*"; }
ok() { printf '  %s✓%s %s\n' "$green" "$reset" "$*"; }
warn() { printf '  %s!%s %s\n' "$yellow" "$reset" "$*"; }
err() { printf '  %s✗%s %s\n' "$red" "$reset" "$*" >&2; }
section() { printf '\n'; line; printf '  %s%s%s\n' "$bold" "$*" "$reset"; line; }
has_tty() { [[ -t 0 || -t 1 || -t 2 ]] && { : </dev/tty; } 2>/dev/null; }
die() { err "$*"; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Не найдена необходимая команда: $1"; }

usage() {
    cat <<'EOF'
mtdd — установка и управление MTProto-прокси

Использование:
  sudo bash install.sh [ПАРАМЕТРЫ]           Установка или обновление
  sudo mtdd-ctl                              Меню управления (после установки)
  sudo bash install.sh КОМАНДА [АРГУМЕНТЫ]   Управление без меню

Команды управления (требуют root):

  status                          Состояние службы, API и пулов ME
  service start|stop|restart      Действие над systemd-службой
  logs [N|follow]                 Журнал: последние N строк (по умолчанию 50) или поток
  users [list]                    Список пользователей
  users add ИМЯ                   Создать пользователя и показать ссылку
  users enable|disable ИМЯ        Включить или отключить пользователя
  users remove ИМЯ [--yes]        Удалить пользователя (без подтверждения с --yes)
  users rotate ИМЯ                Заменить секрет и показать новую ссылку
  links [ИМЯ]                     Ссылки подключения (все или одного)
  rotate ИМЯ                      То же, что users rotate
  metrics [ФИЛЬТР|all]            Метрики Prometheus (по умолчанию только mtdd_)
  host АДРЕС [ПОРТ]               Сменить публичный адрес ссылок и перезапустить
  check-config                    Проверить конфигурацию бинарником
  update [--branch main|dev]      Обновить бинарник (то же, что повторная установка)
  uninstall [--yes]               Удалить прокси с сервера
  menu                            Меню управления

Настройка новой установки:

  --domain HOST           Домен маскировки FakeTLS
  --ad-tag HEX            Ненулевой рекламный тег Telegram (32 hex)
  --port PORT             Порт прокси (по умолчанию 443)
  --user NAME             Первый пользователь (по умолчанию admin)
  --public-host HOST      Внешний IP или DNS (по умолчанию автоопределение)
  --public-port PORT      Внешний порт при NAT (по умолчанию --port)

Сборка и режим работы:

  --branch main|dev       Канал бинарника (по умолчанию main)
  --binary-only           Скачать бинарник без установки службы
  --output PATH           Путь для --binary-only
  --repo OWNER/REPO       Репозиторий релизов (по умолчанию ugDeDe/mtdd)
  --base-url URL          HTTPS-зеркало каталога релизов
  -h, --help              Показать справку

API: 127.0.0.1:9090. При обновлении пользователи и токен сохраняются.
Ссылка подключения выводится после установки и содержит секрет пользователя.
EOF
}

# Разбор аргументов: первый позиционный токен — подкоманда управления,
# остальные позиционные — её аргументы; флаги принадлежат установщику.
SUBCOMMANDS=" status service start stop restart logs users links rotate metrics host check-config update uninstall menu help "
positional=()
while (($#)); do
    case $1 in
        --repo|--branch|--domain|--ad-tag|--port|--public-host|--public-port|--user|--output|--base-url)
            (($# >= 2)) || die "Не указано значение для $1"
            case $1 in
                --repo) repo=$2 ;; --branch) channel=$2; channel_set=1 ;; --domain) domain=$2 ;;
                --ad-tag) ad_tag=$2 ;; --port) proxy_port=$2; port_set=1 ;; --user) user_name=$2; user_set=1 ;;
                --public-host) public_host=$2 ;; --public-port) public_port=$2 ;;
                --output) output=$2 ;; --base-url) base_url=$2 ;;
            esac
            shift 2 ;;
        --binary-only) binary_only=1; shift ;;
        --yes) yes_flag=1; shift ;;
        -h|--help) usage; exit 0 ;;
        -*) die "Неизвестный параметр: $1 (справка: --help)" ;;
        *) positional+=("$1"); shift ;;
    esac
done
if ((${#positional[@]})); then
    command=${positional[0]}
    if [[ $SUBCOMMANDS != *" $command "* ]]; then
        die "Неизвестная команда: $command (справка: --help)"
    fi
    cargs=("${positional[@]:1}")
fi
[[ $command == update ]] && command= # обновление — это повторный запуск установщика
if [[ -n $command && $binary_only == 1 ]]; then
    die 'Команды управления несовместимы с --binary-only'
fi
[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die 'Неверный репозиторий; используйте OWNER/REPO'

# ---------------------------------------------------------------------------
# Общие валидаторы (установщик и команда host)
# ---------------------------------------------------------------------------
valid_dns_name() {
    python3 - "$1" <<'PY'
import re
import sys
name = sys.argv[1]
labels = name.split('.')
ok = len(name) <= 253 and all(
    1 <= len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label)
    for label in labels
)
sys.exit(0 if ok else 1)
PY
}

valid_public_host() {
    python3 - "$1" <<'PY'
import ipaddress, re, sys
host = sys.argv[1]
try:
    valid = not ipaddress.ip_address(host).is_unspecified
except ValueError:
    valid = len(host) <= 253 and all(
        1 <= len(label) <= 63 and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?', label)
        for label in host.split('.'))
sys.exit(0 if valid else 1)
PY
}

valid_port() {
    [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

valid_user_name() {
    [[ $1 =~ ^[A-Za-z0-9_.-]{1,64}$ ]]
}

prompt() {
    local variable=$1 label=$2 fallback=${3-} answer
    has_tty || die "$label: требуется значение (укажите его параметром при запуске без терминала)"
    printf '  → %s%s: ' "$label" "${fallback:+ [$fallback]}" >/dev/tty
    IFS= read -r answer </dev/tty || die "Не удалось прочитать ответ: $label"
    printf -v "$variable" '%s' "${answer:-$fallback}"
}

confirm() { # confirm ВОПРОС -> 0 при подтверждении; без терминала — отказ
    local answer
    has_tty || return 1
    printf '  → %s [y/N]: ' "$1" >/dev/tty
    IFS= read -r answer </dev/tty || return 1
    [[ $answer == y || $answer == Y || $answer == да ]]
}

# ---------------------------------------------------------------------------
# Режим управления: доступ к локальному API и службе
# ---------------------------------------------------------------------------
mg_require_root() {
    ((EUID == 0)) || { err 'Требуются права root: запустите через sudo'; return 1; }
}

mg_require_install() {
    if [[ ! -f $MTDD_CONF || ! -f $MTDD_CREDS ]]; then
        err 'mtdd не установлен или установка неполная; выполните: sudo bash install.sh'
        return 1
    fi
}

mg_require_tools() {
    need curl
    need python3
    need systemctl
}

cfg_get() { # cfg_get КЛЮЧ [ПО_УМОЛЧАНИЮ]
    python3 - "$MTDD_CONF" "$1" "${2-}" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
value = cfg.get(sys.argv[2], sys.argv[3])
print(value if value is not None else "")
PY
}

token_read() {
    local token
    token=$(sed -n 's/^\(export \)\{0,1\}MTDD_API_TOKEN=\([A-Za-z0-9]\{32,512\}\)$/\2/p' "$MTDD_CREDS" | head -1)
    [[ -n $token ]] || { err "В $MTDD_CREDS нет корректного MTDD_API_TOKEN"; return 1; }
    printf '%s' "$token"
}

api() { # api МЕТОД ПУТЬ [JSON-ТЕЛО] — печатает тело ответа или завершается ошибкой
    local method=$1 path=$2 body=${3-} token host port
    token=$(token_read) || return 1
    host=$(cfg_get control_host 127.0.0.1)
    port=$(cfg_get control_port 9090)
    [[ $host == 0.0.0.0 || $host == '::' || $host == '*' ]] && host=127.0.0.1
    [[ $host == *:* ]] && host="[$host]"
    local -a extra=()
    [[ -n $body ]] && extra+=(-H 'Content-Type: application/json' -d "$body")
    curl -fsS --max-time 10 -X "$method" -H "Authorization: Bearer $token" \
        "${extra[@]}" "http://${host}:${port}${path}"
}

api_endpoint() {
    local host port
    host=$(cfg_get control_host 127.0.0.1)
    port=$(cfg_get control_port 9090)
    [[ $host == 0.0.0.0 || $host == '::' || $host == '*' ]] && host=127.0.0.1
    printf 'http://%s:%s' "$host" "$port"
}

cmd_status() {
    local active enabled health ready
    active=$(systemctl is-active "$MTDD_SERVICE" 2>/dev/null || true)
    enabled=$(systemctl is-enabled "$MTDD_SERVICE" 2>/dev/null || true)
    section 'mtdd · состояние'
    step "Служба: ${active:-unknown} · автозапуск: ${enabled:-unknown}"
    health=$(api GET /v1/health 2>/dev/null) || health=
    ready=$(api GET /v1/ready 2>/dev/null) || ready=
    if [[ -z $health && -z $ready ]]; then
        warn "API ($(api_endpoint)) не отвечает"
        warn 'Служба может запускаться или завершилась с ошибкой; журнал: sudo install.sh logs 100'
        return 1
    fi
    step "health: $health"
    step "ready:  $ready"
    local summary
    summary=$(api GET /v1/status 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin).get("data", {})
except Exception:
    sys.exit(1)
print("  Аптайм: {} с · активных соединений: {} · принято: {} · отклонено: {}".format(
    data.get("uptime_seconds", "?"), data.get("connections_active", "?"),
    data.get("connections_accepted_total", "?"), data.get("connections_rejected_total", "?")))
for dc in data.get("me_dcs", []):
    print("  DC {} · подключен: {} · соединений: {} · готовых: {} · переподключений: {}".format(
        dc.get("dc", "?"), dc.get("connected", "?"), dc.get("connections", "?"),
        dc.get("ready_connections", "?"), dc.get("reconnects_total", "?")))
') || summary=
    if [[ -n $summary ]]; then
        printf '%s\n' "$summary"
        return 0
    fi
    warn 'Не удалось получить /v1/status'
    return 1
}

cmd_service() {
    local action=${1-}
    case $action in
        start|stop|restart) ;;
        *) err 'Использование: install.sh service start|stop|restart'; return 1 ;;
    esac
    systemctl "$action" "$MTDD_SERVICE" || { err "systemctl $action завершился с ошибкой"; return 1; }
    ok "Служба: systemctl $action выполнен · состояние: $(systemctl is-active "$MTDD_SERVICE" 2>/dev/null || echo unknown)"
}

cmd_logs() {
    need journalctl
    local arg=${1:-50}
    case $arg in
        follow|f|-f)
            step 'Журнал в реальном времени (Ctrl+C — выход)…'
            journalctl -u "$MTDD_SERVICE" -f --no-pager ;;
        ''|*[!0-9]*)
            err 'Использование: install.sh logs [ЧИСЛО|follow]'; return 1 ;;
        *)
            journalctl -u "$MTDD_SERVICE" -n "$arg" --no-pager ;;
    esac
}

cmd_users_list() {
    local out
    out=$(api GET /v1/users 2>/dev/null) || { err 'Не удалось получить список пользователей'; return 1; }
    printf '%s' "$out" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)["data"]
except Exception:
    sys.exit(1)
users = data["users"]
print("  Пользователей: {} · ревизия: {}".format(len(users), data.get("revision", "?")))
if not users:
    sys.exit(0)
print("  {:<20} {:<4} {:>10} {:>12}".format("Имя", "Вкл", "Соединений", "Уникальных IP"))
for u in users:
    stats = u.get("stats", {})
    print("  {:<20} {:<4} {:>10} {:>12}".format(
        str(u.get("name", "?")), "да" if u.get("enabled") else "нет",
        str(stats.get("active_connections", 0)), str(stats.get("unique_ips_active", 0))))
' || { err 'Не удалось разобрать список пользователей'; return 1; }
}

print_user_link() { # print_user_link ИМЯ — печатает ссылку из API
    local name=$1 response
    response=$(api GET "/v1/users/$name/links" 2>/dev/null) \
        || { err "Не удалось получить ссылку для $name"; return 1; }
    printf '%s' "$response" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)["data"]
except Exception:
    sys.exit(1)
links = data.get("links", {})
mark = "" if data.get("enabled") else " (disabled)"
print("  {}{}: {}".format(data.get("name", "?"), mark, links.get("telegram", "")))
print("  tg://: {}".format(links.get("native", "")))
' || { err "Не удалось разобрать ссылку для $name"; return 1; }
}

cmd_users_add() {
    local name=$1 response secret
    valid_user_name "$name" || { err 'Имя: 1–64 символа A–Z, a–z, 0–9, _ . -'; return 1; }
    response=$(api POST /v1/users "{\"name\":\"$name\"}" 2>/dev/null) \
        || { err "Не удалось создать $name (уже существует?)"; return 1; }
    secret=$(printf '%s' "$response" | python3 -c 'import json, sys; print(json.load(sys.stdin)["data"].get("secret", ""))') || secret=
    [[ -n $secret ]] && warn "Секрет $name (показывается один раз): $secret"
    print_user_link "$name"
    warn 'Ссылка содержит секрет. Передавайте её только этому пользователю.'
}

cmd_users_set_enabled() {
    local name=$1 value=$2 verb=$3
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    api PATCH "/v1/users/$name" "{\"enabled\":$value}" >/dev/null 2>&1 \
        || { err "Не удалось изменить $name (нет такого пользователя?)"; return 1; }
    ok "Пользователь $name: $verb · активные сессии отозваны"
    [[ $value == true ]] || warn 'Отключённый пользователь не может подключаться до включения'
}

cmd_users_remove() {
    local name=$1 force=${2-}
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    if [[ $force != --yes && $yes_flag != 1 ]]; then
        confirm "Удалить пользователя $name? Ссылка перестанет работать" \
            || { warn "Удаление $name отменено"; return 1; }
    fi
    api DELETE "/v1/users/$name" >/dev/null 2>&1 \
        || { err "Не удалось удалить $name (нет такого пользователя?)"; return 1; }
    ok "Пользователь $name удалён, сессии отозваны"
}

cmd_users_rotate() {
    local name=$1
    valid_user_name "$name" || { err 'Неверное имя пользователя'; return 1; }
    api POST "/v1/users/$name/rotate-secret" '{}' >/dev/null 2>&1 \
        || { err "Не удалось заменить секрет $name (нет такого пользователя?)"; return 1; }
    ok "Секрет $name заменён; старая ссылка больше не работает"
    print_user_link "$name"
    warn 'Передайте пользователю новую ссылку.'
}

cmd_users() {
    local action=${1-list}
    case $action in
        list)
            cmd_users_list ;;
        add)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users add ИМЯ'; return 1; }
            cmd_users_add "${cargs[1]}" ;;
        enable)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users enable ИМЯ'; return 1; }
            cmd_users_set_enabled "${cargs[1]}" true 'включён' ;;
        disable)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users disable ИМЯ'; return 1; }
            cmd_users_set_enabled "${cargs[1]}" false 'отключён' ;;
        remove|delete)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users remove ИМЯ [--yes]'; return 1; }
            cmd_users_remove "${cargs[1]}" "${cargs[2]-}" ;;
        rotate)
            ((${#cargs[@]} >= 2)) || { err 'Использование: install.sh users rotate ИМЯ'; return 1; }
            cmd_users_rotate "${cargs[1]}" ;;
        *)
            err "Неизвестное действие users: $action (list|add|enable|disable|remove|rotate)"
            return 1 ;;
    esac
}

cmd_links() {
    if ((${#cargs[@]} >= 1)); then
        print_user_link "${cargs[0]}"
        return
    fi
    local names rc=0 name
    names=$(api GET /v1/users 2>/dev/null | python3 -c 'import json, sys; d = json.load(sys.stdin)["data"]["users"]; print("\n".join(u["name"] for u in d))') \
        || { err 'Не удалось получить список пользователей'; return 1; }
    [[ -n $names ]] || { warn 'Пользователей нет'; return 0; }
    while IFS= read -r name; do
        print_user_link "$name" || rc=1
    done <<< "$names"
    return "$rc"
}

cmd_rotate() {
    ((${#cargs[@]} >= 1)) || { err 'Использование: install.sh rotate ИМЯ'; return 1; }
    cmd_users_rotate "${cargs[0]}"
}

cmd_metrics() {
    local filter=${1-} out lines
    out=$(api GET /metrics 2>/dev/null) || { err 'Не удалось получить метрики'; return 1; }
    if [[ $filter == all ]]; then
        printf '%s\n' "$out"
        return 0
    fi
    lines=$(printf '%s\n' "$out" | grep -E '^mtdd_' || true)
    if [[ -n $filter ]]; then
        lines=$(printf '%s\n' "$lines" | grep -F -- "$filter" || true)
    fi
    [[ -n $lines ]] || { warn 'Метрики mtdd_ не найдены'; return 0; }
    printf '%s\n' "$lines"
}

cmd_host() {
    ((${#cargs[@]} >= 1)) || { err 'Использование: install.sh host АДРЕС [ПОРТ]'; return 1; }
    local host=$1 port=${2-} candidate
    valid_public_host "$host" || { err 'Неверный публичный адрес; укажите IP или DNS-имя'; return 1; }
    if [[ -n $port ]]; then
        valid_port "$port" || { err 'Порт должен быть в диапазоне 1–65535'; return 1; }
    fi
    candidate=$(mktemp /etc/mtdd/.config.XXXXXXXX)
    MTDD_NEW_HOST=$host MTDD_NEW_PORT=$port python3 - "$candidate" <<'PY' || { rm -f -- "$candidate"; err 'Не удалось обновить конфигурацию'; return 1; }
import json, os, sys
from pathlib import Path
config = json.loads(Path('/etc/mtdd/config.json').read_text())
config['public_host'] = os.environ['MTDD_NEW_HOST']
if os.environ['MTDD_NEW_PORT']:
    config['public_port'] = int(os.environ['MTDD_NEW_PORT'])
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + '\n')
PY
    chown root:mtdd "$candidate"
    chmod 0640 "$candidate"
    mv -f -- "$candidate" "$MTDD_CONF"
    ok "Публичный адрес: $host${port:+:$port}"
    if ! "$MTDD_BIN" --config "$MTDD_CONF" --check-config >/dev/null; then
        err 'Проверка конфигурации не пройдена'
        return 1
    fi
    systemctl restart "$MTDD_SERVICE" || { err 'Не удалось перезапустить службу'; return 1; }
    ok 'Служба перезапущена; новые ссылки:'
    cargs=()
    cmd_links
}

cmd_check_config() {
    [[ -x $MTDD_BIN ]] || { err "Бинарник не найден: $MTDD_BIN"; return 1; }
    "$MTDD_BIN" --config "$MTDD_CONF" --check-config \
        && ok 'Конфигурация корректна'
}

cmd_uninstall() {
    local force=${1-}
    if [[ ! -e $MTDD_UNIT && ! -e $MTDD_BIN && ! -e $MTDD_CONF ]]; then
        err 'Установка mtdd не найдена'
        return 1
    fi
    if [[ $force != --yes && $yes_flag != 1 ]]; then
        section 'mtdd · удаление'
        warn 'Будут остановлены служба и удалены бинарники.'
        confirm 'Продолжить удаление службы и бинарников?' \
            || { warn 'Удаление отменено'; return 1; }
    fi
    systemctl disable --now "$MTDD_SERVICE" 2>/dev/null || warn 'Служба уже неактивна или отсутствует'
    rm -f -- "$MTDD_UNIT"
    systemctl daemon-reload 2>/dev/null || true
    rm -f -- "$MTDD_BIN" "$MTDD_CTL"
    ok 'Служба, бинарник и менеджер mtdd-ctl удалены'
    local remove_state=0
    if [[ $force == --yes || $yes_flag == 1 ]]; then
        remove_state=1
    elif confirm 'Удалить конфигурацию, токен и пользователей (/etc/mtdd, /var/lib/mtdd)?'; then
        remove_state=1
    fi
    if ((remove_state)); then
        rm -rf -- /etc/mtdd "$MTDD_STATE"
        getent passwd mtdd >/dev/null 2>&1 && userdel mtdd 2>/dev/null || true
        ok 'Конфигурация, токен и пользователи удалены'
    else
        warn "Сохранено: $MTDD_CONF, $MTDD_CREDS, $MTDD_STATE"
        warn 'Повторная установка подхватит сохранённые данные; для полной очистки удалите их вручную.'
    fi
    ok 'mtdd удалён с сервера'
}

# ---------------------------------------------------------------------------
# Меню управления
# ---------------------------------------------------------------------------
menu_read() { # menu_read ПЕРЕМЕННАЯ ПРИГЛАШЕНИЕ
    local answer
    printf '%s' "$2" >/dev/tty
    IFS= read -r answer </dev/tty || return 1
    printf -v "$1" '%s' "$answer"
}

menu_pause() {
    menu_read _ '  Нажмите Enter, чтобы продолжить… ' || true
}

menu_run() { # menu_run КОМАНДА [АРГУМЕНТЫ…] — не даёт set -e уронить меню
    printf '\n'
    set +e
    "$@"
    local rc=$?
    set -e
    ((rc == 0)) || warn "Команда завершилась с ошибкой (код $rc)"
    return 0
}

menu_users() {
    local choice name
    while :; do
        section 'Пользователи'
        printf '  1) Список          4) Отключить\n' >/dev/tty
        printf '  2) Добавить        5) Удалить\n' >/dev/tty
        printf '  3) Включить        6) Новый секрет (ротация)\n' >/dev/tty
        printf '  0) Назад\n' >/dev/tty
        menu_read choice '  → Выбор: ' || return 0
        case $choice in
            1)
                menu_run cmd_users_list
                menu_pause ;;
            2)
                menu_read name '  → Имя нового пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_add "$name"
                menu_pause ;;
            3)
                menu_read name '  → Имя пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_set_enabled "$name" true 'включён'
                menu_pause ;;
            4)
                menu_read name '  → Имя пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_set_enabled "$name" false 'отключён'
                menu_pause ;;
            5)
                menu_read name '  → Имя пользователя: ' || return 0
                if [[ -n $name ]] && confirm "Удалить пользователя $name? Ссылка перестанет работать"; then
                    menu_run cmd_users_remove "$name" --yes
                fi
                menu_pause ;;
            6)
                menu_read name '  → Имя пользователя: ' || return 0
                [[ -n $name ]] && menu_run cmd_users_rotate "$name"
                menu_pause ;;
            0|q|Q) return 0 ;;
            *) : ;;
        esac
    done
}

run_installer_channel() { # обновление бинарника из меню в изолированном подпроцессе
    local choice
    printf '  Каналы: 1) main — основной  2) dev — тестовый\n' >/dev/tty
    menu_read choice '  → Канал [main]: ' || return 0
    case $choice in
        2|dev) channel=dev ;;
        *) channel=main ;;
    esac
    channel_set=1
    printf '\n'
    set +e
    (run_install)
    local rc=$?
    set -e
    ((rc == 0)) || warn "Обновление завершилось с ошибкой (код $rc)"
    return 0
}

cmd_menu() {
    mg_require_root || return 1
    mg_require_install || return 1
    mg_require_tools || return 1
    has_tty || die 'Меню требует терминала; используйте подкоманды (справка: --help)'
    local choice host port
    while :; do
        section 'mtdd · управление прокси'
        printf '  1) Статус               6) Метрики\n' >/dev/tty
        printf '  2) Пользователи         7) Обновить бинарник\n' >/dev/tty
        printf '  3) Ссылки               8) Публичный адрес\n' >/dev/tty
        printf '  4) Журнал               9) Проверить конфигурацию\n' >/dev/tty
        printf '  5) Перезапуск службы    0) Выход\n' >/dev/tty
        menu_read choice '  → Выбор: ' || break
        case $choice in
            1)
                menu_run cmd_status
                menu_pause ;;
            2) menu_users ;;
            3)
                menu_run cmd_links
                menu_pause ;;
            4)
                menu_run cmd_logs 50
                menu_pause ;;
            5)
                menu_run cmd_service restart
                menu_pause ;;
            6)
                menu_run cmd_metrics
                menu_pause ;;
            7)
                step 'Обновление скачает бинарник выбранного канала и перезапустит службу.'
                run_installer_channel
                break ;;
            8)
                menu_read host '  → Публичный IP или DNS: ' || break
                menu_read port '  → Публичный порт (Enter — не менять): ' || break
                if [[ -n $host ]]; then
                    menu_run cmd_host "$host" "$port"
                fi
                menu_pause ;;
            9)
                menu_run cmd_check_config
                menu_pause ;;
            0|q|Q) break ;;
            *) : ;;
        esac
    done
    printf '\n'
    ok 'Готово'
}

# ---------------------------------------------------------------------------
# Режим установки и обновления
# ---------------------------------------------------------------------------
init_base_url() {
    if [[ -z $base_url ]]; then base_url="https://github.com/$repo/releases/download"; fi
    case $base_url in
        https://*) ;;
        http://127.0.0.1:*|http://localhost:*) ;;
        *) die 'Зеркало должно использовать HTTPS (HTTP разрешён только для localhost)' ;;
    esac
    base_url=${base_url%/}
}

print_links_from_files() {
    python3 - <<'PY'
import json
from pathlib import Path
from urllib.parse import urlencode
config = json.loads(Path('/etc/mtdd/config.json').read_text())
users_path = Path(config['users_path'])
if not users_path.is_absolute():
    users_path = Path('/etc/mtdd') / users_path
users = json.loads(users_path.read_text())['users']
for user in users:
    query = urlencode({'server': config['public_host'],
                       'port': config.get('public_port', config['proxy_port']),
                       'secret': 'ee' + user['secret'] + config['tls_domain'].encode('ascii').hex()})
    print(f"  {user['name']}{' (disabled)' if not user['enabled'] else ''}: https://t.me/proxy?{query}")
PY
}

install_launcher_copy() {
    local src=${BASH_SOURCE[0]:-}
    if [[ -z $src || $src == /dev/stdin || $src == /dev/fd/* || ! -f $src || ! -s $src ]]; then
        warn 'Установщик запущен через pipe; mtdd-ctl не установлен — управляйте этим же скриптом'
        return 0
    fi
    if install -m 0755 "$src" "$MTDD_CTL"; then
        ok "Менеджер управления: sudo mtdd-ctl ($MTDD_CTL)"
    else
        warn 'Не удалось установить mtdd-ctl; управление доступно через этот же скрипт'
    fi
}

download_and_stage() {
    work=$(mktemp -d)
    trap 'rm -rf -- "$work"' EXIT
    asset=mtdd-linux-x86_64
    url="$base_url/channel-$channel"
    step "Скачиваю бинарник и контрольную сумму канала $channel…"
    curl -fsSL --retry 3 --connect-timeout 20 "$url/$asset" -o "$work/$asset" || die 'Не удалось скачать бинарник; проверьте доступность release-канала'
    curl -fsSL --retry 3 --connect-timeout 20 "$url/SHA256SUMS" -o "$work/SHA256SUMS" || die 'Не удалось скачать контрольные суммы'
    step 'Проверяю SHA-256 скачанного бинарника…'
    digest=$(awk -v name="$asset" '$2 == name {print $1; count++} END {if (count != 1) exit 1}' "$work/SHA256SUMS") || die 'Некорректный файл контрольных сумм'
    [[ $digest =~ ^[[:xdigit:]]{64}$ ]] || die 'Некорректная контрольная сумма SHA-256'
    printf '%s  %s\n' "$digest" "$work/$asset" | sha256sum -c - >/dev/null || die 'Контрольная сумма бинарника не совпадает'
    target_dir=$(dirname -- "$output")
    [[ -d $target_dir ]] || die "Каталог назначения не существует: $target_dir"
    staged=$(mktemp "$target_dir/.mtdd.XXXXXXXX")
    trap 'rm -rf -- "$work"; rm -f -- "$staged"' EXIT
    install -m 0755 "$work/$asset" "$staged"
}

run_install() {
    init_base_url
    section 'mtdd · установка MTProto-прокси'
    ((EUID == 0)) || die 'Для установки службы нужны права root: запустите через sudo'
    [[ $output == /usr/local/bin/mtdd ]] || die '--output доступен только вместе с --binary-only'
    for cmd in python3 systemctl useradd getent; do need "$cmd"; done
    [[ -d /run/systemd/system ]] || die 'Для установки службы требуется systemd'
    if [[ -e $MTDD_CONF || -e $MTDD_CREDS ]]; then
        [[ -f $MTDD_CONF && -f $MTDD_CREDS ]] ||
            die 'Предыдущая установка неполная; сохраните и проверьте /etc/mtdd перед повтором'
        fresh=0
    else
        fresh=1
        needs_dialog=0
        if [[ -z $domain || -z $ad_tag ]]; then needs_dialog=1; fi
        [[ ! -e $MTDD_STATE/users.json ]] || die 'Найдены существующие пользователи; перезапись запрещена'
        section 'Настройка прокси'
        step 'FakeTLS-домен — маскировка, а не адрес вашего сервера.'
        if ((needs_dialog)); then
            has_tty || die 'Для новой установки укажите --domain и --ad-tag (либо запустите установщик в терминале)'
            if ((!channel_set)); then
                printf '  Каналы: main — основной, dev — тестовый\n\n' >/dev/tty
                prompt channel 'Канал сборки (main/dev)' "$channel"
                [[ $channel == main || $channel == dev ]] || die 'Для --branch укажите main или dev'
            fi
            [[ -n $domain ]] || prompt domain 'Домен FakeTLS'
            [[ -n $ad_tag ]] || prompt ad_tag 'Рекламный тег Telegram (32 hex)'
            ((!port_set)) && prompt proxy_port 'TCP-порт прокси' "$proxy_port"
            ((!user_set)) && prompt user_name 'Имя первого пользователя' "$user_name"
        fi
        [[ -n $domain ]] || die 'Укажите домен FakeTLS через --domain'
        [[ -n $ad_tag ]] || die 'Укажите рекламный тег через --ad-tag'
    fi
    if ((fresh)); then
        [[ $ad_tag =~ ^[[:xdigit:]]{32}$ && $ad_tag != 00000000000000000000000000000000 ]] || die 'Тег должен содержать 32 hex-символа и не состоять из нулей'
        valid_port "$proxy_port" || die 'Порт прокси должен быть в диапазоне 1–65535'
        [[ $user_name =~ ^[A-Za-z0-9_-]{1,32}$ ]] || die 'Имя пользователя: 1–32 символа A–Z, a–z, 0–9, _ или -'
        valid_dns_name "$domain" || die 'Неверное DNS-имя FakeTLS'
    fi
    if ((!fresh)) && [[ -z $public_host ]]; then
        public_host=$(python3 -c "import json; print(json.load(open('$MTDD_CONF')).get('public_host', ''))") || die 'Не удалось прочитать существующую конфигурацию'
    fi
    if [[ -z $public_host ]]; then
        step 'Определяю внешний IPv4-адрес…'
        public_host=$(curl -4fsS --connect-timeout 3 --max-time 5 https://api.ipify.org 2>/dev/null || true)
        if ! valid_public_host "$public_host"; then public_host=; fi
        if [[ -z $public_host ]]; then
            if has_tty; then
                prompt public_host 'Публичный IP или DNS сервера'
            else
                die 'Не удалось определить публичный IP; укажите --public-host'
            fi
        fi
    fi
    valid_public_host "$public_host" || die 'Неверный публичный адрес; укажите IP или DNS-имя'
    if [[ -n $public_port ]]; then
        valid_port "$public_port" || die 'Публичный порт должен быть в диапазоне 1–65535'
    fi
    section 'Параметры установки'
    if ((fresh)); then
        step "Режим: новая установка · канал: $channel"
        step "FakeTLS: $domain · локальный порт: $proxy_port · пользователь: $user_name"
    else
        step "Режим: обновление · канал: $channel · пользователи и токен сохраняются"
    fi
    step "Публичный адрес для ссылок: $public_host${public_port:+:$public_port}"

    download_and_stage

    if ! getent passwd mtdd >/dev/null; then
        useradd --system --user-group --home-dir "$MTDD_STATE" --shell /usr/sbin/nologin mtdd
    fi
    step 'Создаю конфигурацию и проверяю её…'
    install -d -m 0750 -o root -g mtdd /etc/mtdd
    install -d -m 0700 -o mtdd -g mtdd "$MTDD_STATE"
    if ((fresh)); then
        MTDD_INSTALL_DOMAIN=$domain MTDD_INSTALL_TAG=$ad_tag MTDD_INSTALL_PORT=$proxy_port \
        MTDD_INSTALL_USER=$user_name MTDD_PUBLIC_HOST=$public_host MTDD_PUBLIC_PORT=$public_port python3 - <<'PY'
import json
import os
import secrets
from pathlib import Path

config = {"proxy_host": "0.0.0.0", "proxy_port": int(os.environ["MTDD_INSTALL_PORT"]),
          "control_host": "127.0.0.1", "control_port": 9090,
          "api_token_env": "MTDD_API_TOKEN", "tls_domain": os.environ["MTDD_INSTALL_DOMAIN"],
          "ad_tag": os.environ["MTDD_INSTALL_TAG"], "users_path": "/var/lib/mtdd/users.json"}
config["public_host"] = os.environ["MTDD_PUBLIC_HOST"]
if os.environ["MTDD_PUBLIC_PORT"]:
    config["public_port"] = int(os.environ["MTDD_PUBLIC_PORT"])
users = {"version": 1, "revision": 1, "users": [{"name": os.environ["MTDD_INSTALL_USER"],
         "secret": secrets.token_hex(16), "enabled": True, "max_connections": None, "generation": 1}]}
Path('/etc/mtdd/config.json').write_text(json.dumps(config, indent=2) + '\n')
Path('/etc/mtdd/credentials.env').write_text('MTDD_API_TOKEN=' + secrets.token_hex(32) + '\n')
Path('/var/lib/mtdd/users.json').write_text(json.dumps(users, indent=2) + '\n')
PY
        chown root:mtdd /etc/mtdd/config.json
        chmod 0640 /etc/mtdd/config.json
        chown root:root /etc/mtdd/credentials.env
        chmod 0600 /etc/mtdd/credentials.env
        chown mtdd:mtdd "$MTDD_STATE/users.json"
        chmod 0600 "$MTDD_STATE/users.json"
    fi
    config_candidate=$(mktemp /etc/mtdd/.config.XXXXXXXX)
    trap 'rm -rf -- "$work"; rm -f -- "$staged" "$config_candidate"' EXIT
    MTDD_PUBLIC_HOST=$public_host MTDD_PUBLIC_PORT=$public_port python3 - "$config_candidate" <<'PY'
import json, os, sys
from pathlib import Path
config = json.loads(Path('/etc/mtdd/config.json').read_text())
config['public_host'] = os.environ['MTDD_PUBLIC_HOST']
if os.environ['MTDD_PUBLIC_PORT']:
    config['public_port'] = int(os.environ['MTDD_PUBLIC_PORT'])
Path(sys.argv[1]).write_text(json.dumps(config, indent=2) + '\n')
PY
    "$staged" --config "$config_candidate" --check-config >/dev/null || die 'Проверка конфигурации не пройдена'
    chown root:mtdd "$config_candidate"
    chmod 0640 "$config_candidate"
    mv -f -- "$config_candidate" "$MTDD_CONF"
    mv -f -- "$staged" "$output"
    install -d -m 0755 /etc/systemd/system
    install -m 0644 /dev/stdin "$MTDD_UNIT" <<'EOF'
[Unit]
Description=mtdd MTProto proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mtdd
Group=mtdd
EnvironmentFile=/etc/mtdd/credentials.env
ExecStart=/usr/local/bin/mtdd --config /etc/mtdd/config.json
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/mtdd

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    step 'Запускаю службу systemd…'
    systemctl enable --now "$MTDD_SERVICE"
    if ((!fresh)); then systemctl restart "$MTDD_SERVICE"; fi
    install_launcher_copy
    section 'Готово · ссылки для Telegram'
    ok "Бинарник: $channel · служба: mtdd"
    warn 'Ссылки содержат секреты. Передавайте их только своим пользователям.'
    printf '\n'
    print_links_from_files
    printf '\n'
    step 'Управление: sudo mtdd-ctl (меню)'
    step 'Состояние:  sudo systemctl status mtdd'
    step 'Журнал:     sudo journalctl -u mtdd -f'
    step 'Настройки:  /etc/mtdd/config.json'
    step 'API-токен:  /etc/mtdd/credentials.env (только root)'
    warn 'Откройте публичный TCP-порт в firewall и настройте NAT при необходимости.'
    line
}

# ---------------------------------------------------------------------------
# Диспетчер
# ---------------------------------------------------------------------------
for cmd_dep in curl sha256sum awk mktemp install; do need "$cmd_dep"; done
if [[ -n $command ]]; then
    case $command in
        help) usage; exit 0 ;;
        menu) mg_require_root && mg_require_install && mg_require_tools && cmd_menu ;;
        status) mg_require_root && mg_require_install && mg_require_tools && cmd_status ;;
        service) mg_require_root && mg_require_install && mg_require_tools && cmd_service "${cargs[0]-}" ;;
        start) mg_require_root && mg_require_install && mg_require_tools && cmd_service start ;;
        stop) mg_require_root && mg_require_install && mg_require_tools && cmd_service stop ;;
        restart) mg_require_root && mg_require_install && mg_require_tools && cmd_service restart ;;
        logs) mg_require_root && mg_require_install && mg_require_tools && cmd_logs "${cargs[0]-}" ;;
        users) mg_require_root && mg_require_install && mg_require_tools && cmd_users "${cargs[@]}" ;;
        links) mg_require_root && mg_require_install && mg_require_tools && cmd_links "${cargs[@]}" ;;
        rotate) mg_require_root && mg_require_install && mg_require_tools && cmd_rotate "${cargs[@]}" ;;
        metrics) mg_require_root && mg_require_install && mg_require_tools && cmd_metrics "${cargs[0]-}" ;;
        host) mg_require_root && mg_require_install && mg_require_tools && cmd_host "${cargs[@]}" ;;
        check-config) mg_require_root && mg_require_install && cmd_check_config ;;
        uninstall) mg_require_root && cmd_uninstall "${cargs[0]-}" ;;
    esac
    exit $?
fi

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'Поддерживается только Linux x86_64'
[[ $channel == main || $channel == dev ]] || die 'Для --branch укажите main или dev'
init_base_url
if ((binary_only)); then
    section 'mtdd · установка MTProto-прокси'
    step "Скачивание бинарника · канал: $channel"
    download_and_stage
    mv -f -- "$staged" "$output"
    ok "Бинарник $channel установлен: $output"
    exit 0
fi
run_install
