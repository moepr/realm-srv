@echo on
set RUST_BACKTRACE=full
echo. > realm.log
::target\release\realm.exe -l 0.0.0.0:61010 -r 192.168.31.111:61010
target\release\realm.exe -c config.toml