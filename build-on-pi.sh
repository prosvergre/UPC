#!/bin/bash
# Запускать ЭТОТ скрипт прямо на Raspberry Pi (Debian arm64), не на
# компьютере для кросс-компиляции — GUI на Fyne использует cgo и системные
# X11/OpenGL библиотеки, которых у меня для ARM64 нет в кросс-инструментах,
# зато на самой Pi они ставятся одной командой apt.
set -e

echo "== Устанавливаю зависимости (нужен sudo) =="
sudo apt update
sudo apt install -y golang-go gcc pkg-config \
  libgl1-mesa-dev xorg-dev libx11-dev libxcursor-dev libxrandr-dev \
  libxinerama-dev libxi-dev libxxf86vm-dev

echo "== Собираю proxycheck (это может занять несколько минут на Pi) =="
go build -ldflags="-s -w" -o proxycheck .

echo "== Готово: ./proxycheck =="
echo "Запуск GUI:  ./proxycheck"
echo "Запуск CLI:  ./proxycheck -h"
