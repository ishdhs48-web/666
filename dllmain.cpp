// language: C++17, target: Windows 11 x64, MSVC
// DLL injection — infinite HP for APlayerCharacter_C
// Health @ 0x06B0, MaxHealth @ 0x0834 (int32 each)
// UWorld chain: GWorld → OwningGameInstance → LocalPlayers[0] → PlayerController → AcknowledgedPawn
// Offsets derived from UE4SS dump — re-derive if game updates

#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <thread>
#include <atomic>

// ─── UE4 GObjects / GWorld ──────────────────────────────────────────────────
// These are pattern-scanned at runtime; no hardcoded exe offset needed
static uintptr_t g_base = 0;

static uintptr_t read_ptr(uintptr_t addr)
{
    uintptr_t val = 0;
    if (!ReadProcessMemory(GetCurrentProcess(),
                           reinterpret_cast<LPCVOID>(addr),
                           &val, sizeof(val), nullptr))
        return 0;
    return val;
}

static int32_t read_i32(uintptr_t addr)
{
    int32_t val = 0;
    ReadProcessMemory(GetCurrentProcess(),
                      reinterpret_cast<LPCVOID>(addr),
                      &val, sizeof(val), nullptr);
    return val;
}

static bool write_i32(uintptr_t addr, int32_t val)
{
    SIZE_T written = 0;
    return WriteProcessMemory(GetCurrentProcess(),
                              reinterpret_cast<LPVOID>(addr),
                              &val, sizeof(val), &written)
           && written == sizeof(val);
}

// ─── GWorld signature scan ───────────────────────────────────────────────────
// Pattern: 48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 74 06  (UWorld* GWorld)
// Resolves the RIP-relative mov
static uintptr_t find_gworld()
{
    const uint8_t pattern[] = {
        0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,  // mov rax, [rip+disp32]
        0x48, 0x8B, 0x88                             // mov rcx, [rax+??]
    };
    const char mask[] = "xxx????xxx";

    MODULEINFO mi{};
    GetModuleInformation(GetCurrentProcess(),
                         GetModuleHandle(nullptr), &mi, sizeof(mi));

    auto* scan_start = reinterpret_cast<uint8_t*>(mi.lpBaseOfDll);
    size_t scan_size = mi.SizeOfImage;

    for (size_t i = 0; i + sizeof(pattern) < scan_size; ++i)
    {
        bool match = true;
        for (size_t j = 0; j < sizeof(pattern); ++j)
        {
            if (mask[j] == 'x' && scan_start[i + j] != pattern[j])
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            // RIP-relative: disp32 at bytes [3..6], RIP = next instruction = i+7
            int32_t disp = *reinterpret_cast<int32_t*>(scan_start + i + 3);
            uintptr_t gworld_ptr = reinterpret_cast<uintptr_t>(scan_start) + i + 7 + disp;
            uintptr_t world = read_ptr(gworld_ptr);
            if (world && (world >> 48) == 0) // basic sanity: kernel space would fail
                return world;
        }
    }
    return 0;
}

// ─── UE4 object chain offsets ────────────────────────────────────────────────
// UWorld
constexpr uintptr_t OFF_OWNING_GAME_INSTANCE = 0x01C0; // UWorld::OwningGameInstance
// UGameInstance
constexpr uintptr_t OFF_LOCAL_PLAYERS        = 0x0038; // UGameInstance::LocalPlayers (TArray)
// ULocalPlayer → UPlayer::PlayerController
constexpr uintptr_t OFF_PLAYER_CONTROLLER    = 0x0030; // UPlayer::PlayerController
// AController → APawn::AcknowledgedPawn (on APlayerController inherits from AController)
constexpr uintptr_t OFF_ACKNOWLEDGED_PAWN    = 0x0360; // APlayerController::AcknowledgedPawn

// APlayerCharacter_C field offsets (from dump)
constexpr uintptr_t OFF_HEALTH     = 0x06B0; // int32 Health
constexpr uintptr_t OFF_MAX_HEALTH = 0x0834; // int32 MaxHealth

// ─── resolve local pawn ───────────────────────────────────────────────────────
static uintptr_t get_local_pawn()
{
    uintptr_t world = find_gworld();
    if (!world) return 0;

    uintptr_t gi = read_ptr(world + OFF_OWNING_GAME_INSTANCE);
    if (!gi) return 0;

    // LocalPlayers is TArray<ULocalPlayer*> — TArray layout: Data ptr @ +0, Count @ +8
    uintptr_t lp_data  = read_ptr(gi + OFF_LOCAL_PLAYERS);
    int32_t   lp_count = read_i32(gi + OFF_LOCAL_PLAYERS + 0x8);
    if (!lp_data || lp_count <= 0) return 0;

    uintptr_t local_player = read_ptr(lp_data); // [0]
    if (!local_player) return 0;

    uintptr_t controller = read_ptr(local_player + OFF_PLAYER_CONTROLLER);
    if (!controller) return 0;

    uintptr_t pawn = read_ptr(controller + OFF_ACKNOWLEDGED_PAWN);
    return pawn;
}

// ─── HP lock thread ──────────────────────────────────────────────────────────
static std::atomic<bool> g_running{ true };

static void hp_thread()
{
    // Re-scan GWorld each tick: handles map loads without needing restart
    while (g_running.load(std::memory_order_relaxed))
    {
        uintptr_t pawn = get_local_pawn();
        if (pawn)
        {
            int32_t max_hp = read_i32(pawn + OFF_MAX_HEALTH);
            if (max_hp > 0)
            {
                int32_t cur_hp = read_i32(pawn + OFF_HEALTH);
                if (cur_hp < max_hp)
                    write_i32(pawn + OFF_HEALTH, max_hp);
            }
        }
        Sleep(16); // ~60 Hz; low enough to snap before death anim triggers
    }
}

// ─── DllMain ─────────────────────────────────────────────────────────────────
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hMod);
        std::thread(hp_thread).detach();
        break;

    case DLL_PROCESS_DETACH:
        g_running.store(false, std::memory_order_relaxed);
        break;
    }
    return TRUE;
}
