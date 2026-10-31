prefix  := env("PREFIX", env("HOME") / ".local")
bindir  := prefix / "bin"
confdir := env("HOME") / ".config/memguard"
logfile := prefix / "state/memguard.log"
plist   := env("HOME") / "Library/LaunchAgents/local.memguard.plist"
cc      := "clang"
cflags  := "-O3 -flto -Wall -Wextra -Werror -Wl,-dead_strip"

build:
    {{cc}} {{cflags}} memguard.c -o memguard

check: build
    ./memguard --self-test

status: build
    ./memguard status

# DANGER: can kill unrelated work. Save everything; opt in with MEMGUARD_ALLOW_STRESS=1.
test-hog: build
    @test "{{ env("MEMGUARD_ALLOW_STRESS", "") }}" = 1 || { echo "Refusing memory stress: save all work, then set MEMGUARD_ALLOW_STRESS=1." >&2; exit 1; }
    sh -c './memguard --hog; [ $? -eq 137 ]'
    tail -n 3 "{{logfile}}"

# Install files only: no LaunchAgent is created or started.
install: build
    mkdir -p "{{bindir}}" "{{prefix}}/state" "{{confdir}}"
    install -m 755 memguard "{{bindir}}/memguard"
    [ -e "{{confdir}}/memguard.conf" ] || cp "{{justfile_directory()}}/memguard.conf" "{{confdir}}/memguard.conf"
    @echo "Installed, not enabled. Run memguard check and memguard --dry-run before just enable."

# Explicit opt-in: starts live killing now and at future logins.
enable: install
    @echo "WARNING: enabling SIGKILL of large processes; unsaved work can be lost." >&2
    mkdir -p "{{ env("HOME") }}/Library/LaunchAgents"
    @printf '%s\n' \
        '<?xml version="1.0" encoding="UTF-8"?>' \
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
        '<plist version="1.0">' \
        '<dict>' \
        '	<key>Label</key><string>local.memguard</string>' \
        '	<key>ProcessType</key><string>Interactive</string>' \
        '	<key>ProgramArguments</key><array><string>{{bindir}}/memguard</string></array>' \
        '	<key>StandardOutPath</key><string>{{logfile}}</string>' \
        '	<key>StandardErrorPath</key><string>{{logfile}}</string>' \
        '	<key>RunAtLoad</key><true/>' \
        '	<key>KeepAlive</key><true/>' \
        '</dict>' \
        '</plist>' > "{{plist}}"
    "{{bindir}}/memguard" start

uninstall:
    -launchctl bootout gui/$(id -u) "{{plist}}" 2>/dev/null
    rm -f "{{plist}}" "{{bindir}}/memguard"

clean:
    rm -f memguard
