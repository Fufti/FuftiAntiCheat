# FuftiAntiCheat C++

A dual-ring anti-cheat protection framework for Windows games written in C++. Designed as an extensible foundation for modern anti-cheat architectures.

---

## English Documentation

### Overview
FuftiAntiCheat utilizes a dual-ring architecture consisting of an external launcher/watchdog (`fuftianticheat.exe`) and an internal in-game protection core (`fuftianticheat.dll`).

### Core Features

1. Filesystem Integrity Verification (SHA-256):
   - Computes standard FIPS 180-4 SHA-256 cryptographic hashes of all game executables and libraries on disk.
   - Prevents binary replacement, malicious proxy DLL injection, and file modification before launch.

2. In-Memory Code Integrity Monitoring (RAM Protection):
   - Calculates a cryptographic baseline hash of the `.text` (executable code) section in physical memory.
   - Continuously scans memory pages for byte patching, inline hooks (JMP/CALL detours), software breakpoints (0xCC / INT 3), and NOP sleds.
   - Triggers an immediate crash if any in-memory code modification is detected.

3. Memory Page Protection Guard:
   - Scans code section pages using `VirtualQuery`.
   - Detects permission elevation (e.g. `PAGE_EXECUTE_READWRITE`, `PAGE_READWRITE`, or `PAGE_GUARD`) typically performed by memory scanners or hooking engines.

4. Hardware Breakpoint Detection (DR0 - DR7):
   - Inspects processor debug registers across all process threads.
   - Detects hardware read/write memory access breakpoints set by debuggers or tools such as Cheat Engine.

5. Direct NTDLL Hook and Syscall Integrity Scan:
   - Verifies entry-point prologues of critical memory management APIs (`NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtOpenProcess`, `NtQueryVirtualMemory`).
   - Identifies user-mode hooks and trampolines (`0xE9`, `0xEB`, `0xFF 0x25`).

6. Anti-Debugging and Kernel Instrumentation Checks:
   - Querying process debug status via `IsDebuggerPresent` and `CheckRemoteDebuggerPresent`.
   - Kernel debug port validation via `NtQueryInformationProcess` (`ProcessDebugPort`, `ProcessDebugObjectHandle`, `ProcessDebugFlags`).
   - Thread hiding via `NtSetInformationThread` using `ThreadHideFromDebugger` (0x11).

7. Process and Window Threat Elimination:
   - Actively detects over 40 known reverse engineering tools, debuggers, decompilers, and cheat utilities (including IDA Pro, x64dbg, Cheat Engine, Process Hacker, ReClass, Scylla, etc.).
   - All signature strings and window titles are obfuscated via compile-time XOR encryption (no plaintext strings in binaries).
   - Upon detection: terminates the suspect tool process (`PROCESS_TERMINATE`) and crashes the host game immediately.

### Project Structure
- `ru/fufti/fuftianticheat/FuftiAntiCheat.cpp` - Unified single-source file compiling into both `.exe` and `.dll`.
- `Test.cpp` - Interactive security verification suite (RAM modifier, RAM reader, fake DLL generator).

### Build Instructions (MinGW / GCC)

1. Build Internal Anti-Cheat Core (`fuftianticheat.dll`):
```cmd
g++ -O2 -std=c++17 -shared -DFUFTI_BUILD_DLL -o fuftianticheat.dll ru/fufti/fuftianticheat/FuftiAntiCheat.cpp -luser32
```

2. Build External Launcher / Watchdog (`fuftianticheat.exe`):
```cmd
g++ -O2 -std=c++17 -DFUFTI_BUILD_EXE -o fuftianticheat.exe ru/fufti/fuftianticheat/FuftiAntiCheat.cpp -luser32
```

3. Build Test Verification Suite (`Test.exe`):
```cmd
g++ -O2 -std=c++17 Test.cpp -o Test.exe
```

---

## Русская документация

### Обзор
FuftiAntiCheat представляет собой двухуровневый комплекс защиты для игр под Windows, написанный на C++. Служит расширяемой базовой основой для построения игрового античита.

Архитектура состоит из двух компонентов: внешнего лаунчера-наблюдателя (`fuftianticheat.exe`) и внедряемого внутреннего ядра защиты (`fuftianticheat.dll`).

### Основной функционал

1. Проверка целостности файлов на диске (SHA-256):
   - Вычисление криптографических хешей SHA-256 исполняемых файлов игры и динамических библиотек.
   - Защита от подмены DLL, подмены исполняемых файлов и модификации игровых ресурсов до старта.

2. Мониторинг целостности кода в оперативной памяти (RAM):
   - Расчет эталонного SHA-256 хеша секции кода (`.text`) в физической памяти после загрузки.
   - Непрерывное сканирование памяти на предмет байт-патчей, инлайн-хуков (JMP/CALL), программных точек останова (0xCC / INT 3) и NOP-инструкций.
   - Моментальный вызов аварийного завершения (краша) при фиксации любых несанкционированных изменений в коде.

3. Контроль атрибутов защиты страниц памяти:
   - Мониторинг прав страниц через `VirtualQuery`.
   - Обнаружение несанкционированной смены прав доступа на `PAGE_EXECUTE_READWRITE`, `PAGE_READWRITE` или установку `PAGE_GUARD`, характерных для инжекторов и сканеров памяти.

4. Обнаружение аппаратных точек останова (DR0 - DR7):
   - Анализ отладочных регистров процессора во всех потоках процесса.
   - Пресечение попыток отслеживания чтения или записи адресов памяти, выставляемых отладчиками или Cheat Engine.

5. Проверка целостности системных вызовов NTDLL:
   - Проверка прологов функций `NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtOpenProcess`, `NtQueryVirtualMemory`.
   - Детект перехватов и трамплинов (`0xE9`, `0xEB`, `0xFF 0x25`).

6. Защита от отладки на уровне ядра:
   - Проверка флагов `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, структуры PEB (`BeingDebugged`, `NtGlobalFlag`).
   - Проверка портов отладки ядра через `NtQueryInformationProcess` (`ProcessDebugPort`, `ProcessDebugObjectHandle`, `ProcessDebugFlags`).
   - Изоляция потоков защиты через `NtSetInformationThread` с флагом `ThreadHideFromDebugger` (0x11).

7. Нейтрализация сторонних процессов и окон:
   - База сигнатур из 40+ отладчиков, дизассемблеров и читерских утилит (IDA Pro, x64dbg, Cheat Engine, Process Hacker, ReClass, Scylla и др.).
   - Все строки и имена окон зашифрованы ключом XOR на этапе компиляции (отсутствие открытых строк в бинарнике).
   - При обнаружении угрозы: принудительное завершение процесса нарушителя (`TerminateProcess`) и моментальный краш игры.

### Команды сборки проекта

Сборка DLL (Внутреннее ядро):
```cmd
g++ -O2 -std=c++17 -shared -DFUFTI_BUILD_DLL -o fuftianticheat.dll ru/fufti/fuftianticheat/FuftiAntiCheat.cpp -luser32
```

Сборка EXE (Внешний лаунчер):
```cmd
g++ -O2 -std=c++17 -DFUFTI_BUILD_EXE -o fuftianticheat.exe ru/fufti/fuftianticheat/FuftiAntiCheat.cpp -luser32
```

Сборка утилиты тестирования (`Test.exe`):
```cmd
g++ -O2 -std=c++17 Test.cpp -o Test.exe
```
